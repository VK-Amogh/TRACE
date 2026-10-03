"""PyTorch CUDA accelerated model fine-tuning engine for SecureBERT vulnerability detection."""

import os
import time
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, random_split
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from trace_engine.intelligence.securebert.classifier import VULN_CATEGORIES
from trace_engine.intelligence.training.dataset import (
    VulnerabilityDataset,
    generate_cybersecurity_training_corpus,
)

logger = logging.getLogger(__name__)
console = Console()


class TrainingConfig(BaseModel):
    """Configuration hyperparameters for model fine-tuning."""
    model_name: str = "ehsanaghaei/SecureBERT"
    epochs: int = 3
    batch_size: int = 8
    learning_rate: float = 2e-5
    weight_decay: float = 0.01
    max_length: int = 256
    val_split: float = 0.15
    fp16: bool = True
    output_dir: str = ".trace/models/securebert-finetuned"


class SecureBERTTrainer:
    """Trains and fine-tunes SecureBERT using PyTorch with NVIDIA GPU acceleration."""

    def __init__(self, config: Optional[TrainingConfig] = None):
        self.config = config or TrainingConfig()
        self.device = self._detect_device()
        self.scaler = torch.amp.GradScaler("cuda") if self.device.type == "cuda" and self.config.fp16 else None

    def _detect_device(self) -> torch.device:
        if torch.cuda.is_available():
            dev_name = torch.cuda.get_device_name(0)
            vram_gb = round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2)
            console.print(f"\n[bold green]GPU Acceleration Active[/bold green]: {dev_name} ({vram_gb} GB VRAM)")
            return torch.device("cuda:0")
        else:
            console.print("\n[yellow]CUDA not available. Using CPU.[/yellow]")
            return torch.device("cpu")

    def train(self) -> Dict[str, Any]:
        """Executes full supervised fine-tuning pipeline on cybersecurity corpus."""
        out_path = Path(self.config.output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        console.print(f"[bold]Loading Base Model & Tokenizer[/bold]: {self.config.model_name}...")
        tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
        model = AutoModelForSequenceClassification.from_pretrained(
            self.config.model_name,
            num_labels=len(VULN_CATEGORIES),
            ignore_mismatched_sizes=True,
        ).to(self.device)

        # 1. Dataset Generation & Splitting
        raw_samples = generate_cybersecurity_training_corpus(multiplier=20)
        full_dataset = VulnerabilityDataset(raw_samples, tokenizer, max_length=self.config.max_length)

        val_size = int(len(full_dataset) * self.config.val_split)
        train_size = len(full_dataset) - val_size
        train_data, val_data = random_split(
            full_dataset,
            [train_size, val_size],
            generator=torch.Generator().manual_seed(42),
        )

        train_loader = DataLoader(train_data, batch_size=self.config.batch_size, shuffle=True)
        val_loader = DataLoader(val_data, batch_size=self.config.batch_size, shuffle=False)

        console.print(
            f"Dataset loaded: [green]{len(full_dataset)} total slices[/green] "
            f"({train_size} train, {val_size} validation, {len(VULN_CATEGORIES)} categories)"
        )

        # 2. Optimization setup
        optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )
        criterion = nn.BCEWithLogitsLoss()

        total_start = time.perf_counter()
        history: List[Dict[str, float]] = []

        console.print(f"\n[bold green]Starting Fine-Tuning ({self.config.epochs} Epochs on {self.device})[/bold green]:")

        for epoch in range(1, self.config.epochs + 1):
            epoch_start = time.perf_counter()
            model.train()
            total_train_loss = 0.0

            with Progress(
                SpinnerColumn(),
                TextColumn(f"[bold cyan]Epoch {epoch}/{self.config.epochs}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Training", total=len(train_loader))

                for batch in train_loader:
                    optimizer.zero_grad()
                    input_ids = batch["input_ids"].to(self.device)
                    attention_mask = batch["attention_mask"].to(self.device)
                    labels = batch["labels"].to(self.device)

                    if self.scaler:
                        with torch.amp.autocast("cuda"):
                            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                            loss = criterion(outputs.logits, labels)
                        self.scaler.scale(loss).backward()
                        self.scaler.step(optimizer)
                        self.scaler.update()
                    else:
                        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                        loss = criterion(outputs.logits, labels)
                        loss.backward()
                        optimizer.step()

                    total_train_loss += loss.item()
                    progress.update(task, advance=1)

            avg_train_loss = round(total_train_loss / len(train_loader), 4)

            # Validation pass
            model.eval()
            total_val_loss = 0.0
            tp = 0
            fp = 0
            fn = 0

            with torch.no_grad():
                for val_batch in val_loader:
                    v_input_ids = val_batch["input_ids"].to(self.device)
                    v_mask = val_batch["attention_mask"].to(self.device)
                    v_labels = val_batch["labels"].to(self.device)

                    if self.scaler:
                        with torch.amp.autocast("cuda"):
                            v_outputs = model(input_ids=v_input_ids, attention_mask=v_mask)
                            v_loss = criterion(v_outputs.logits, v_labels)
                    else:
                        v_outputs = model(input_ids=v_input_ids, attention_mask=v_mask)
                        v_loss = criterion(v_outputs.logits, v_labels)

                    total_val_loss += v_loss.item()

                    preds = (torch.sigmoid(v_outputs.logits) > 0.5).float()
                    tp += ((preds == 1) & (v_labels == 1)).sum().item()
                    fp += ((preds == 1) & (v_labels == 0)).sum().item()
                    fn += ((preds == 0) & (v_labels == 1)).sum().item()

            avg_val_loss = round(total_val_loss / len(val_loader), 4)
            precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
            recall = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
            f1 = round(2 * precision * recall / (precision + recall), 3) if (precision + recall) > 0 else 0.0
            duration = round(time.perf_counter() - epoch_start, 2)

            console.print(
                f"  Epoch {epoch}: Train Loss: [cyan]{avg_train_loss}[/cyan] | "
                f"Val Loss: [yellow]{avg_val_loss}[/yellow] | "
                f"Precision: [green]{int(precision * 100)}%[/green] | "
                f"Recall: [green]{int(recall * 100)}%[/green] | "
                f"F1: [bold green]{f1}[/bold green] ({duration}s)"
            )

            history.append({
                "epoch": epoch,
                "train_loss": avg_train_loss,
                "val_loss": avg_val_loss,
                "precision": precision,
                "recall": recall,
                "f1": f1,
            })

        total_time = round(time.perf_counter() - total_start, 2)
        console.print(f"\n[bold green]✓ Training Complete in {total_time}s![/bold green]")

        # 3. Save fine-tuned checkpoint & artifacts
        console.print(f"Saving fine-tuned model checkpoint to [dim]{out_path}[/dim]...")
        model.save_pretrained(out_path)
        tokenizer.save_pretrained(out_path)

        metadata = {
            "base_model": self.config.model_name,
            "categories": VULN_CATEGORIES,
            "epochs": self.config.epochs,
            "final_f1": history[-1]["f1"] if history else 0.0,
            "device": str(self.device),
            "training_time_seconds": total_time,
            "history": history,
        }
        with open(out_path / "training_metadata.json", "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        console.print(f"[bold green]Model successfully deployed to {out_path}![/bold green]\n")
        return metadata
