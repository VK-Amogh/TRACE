"""PyTorch CUDA accelerated model fine-tuning engine for SecureBERT with dynamic calibration."""

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
    epochs: int = 5
    batch_size: int = 16
    learning_rate: float = 3e-5
    weight_decay: float = 0.01
    max_length: int = 256
    val_split: float = 0.15
    fp16: bool = True
    output_dir: str = ".trace/models/securebert-finetuned"


class SecureBERTTrainer:
    """Trains and fine-tunes SecureBERT using PyTorch with NVIDIA GPU acceleration and calibrated thresholds."""

    def __init__(self, config: Optional[TrainingConfig] = None):
        self.config = config or TrainingConfig()
        self.device = self._detect_device()
        self.scaler = torch.amp.GradScaler("cuda") if self.device.type == "cuda" and self.config.fp16 else None

    def _detect_device(self) -> torch.device:
        if torch.cuda.is_available():
            dev_name = torch.cuda.get_device_name(0)
            vram_gb = round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2)
            console.print(f"\n[bold green]GPU Acceleration Active[/bold green]: {dev_name} ({vram_gb} GB VRAM, Mixed Precision: {'FP16' if self.config.fp16 else 'FP32'})")
            return torch.device("cuda:0")
        else:
            console.print("\n[yellow]CUDA not available. Using CPU.[/yellow]")
            return torch.device("cpu")

    def train(self) -> Dict[str, Any]:
        """Executes full supervised fine-tuning pipeline on comprehensive cybersecurity corpus."""
        out_path = Path(self.config.output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        console.print(f"[bold]Loading Base Checkpoint & Tokenizer[/bold]: {self.config.model_name}...")
        tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
        model = AutoModelForSequenceClassification.from_pretrained(
            self.config.model_name,
            num_labels=len(VULN_CATEGORIES),
            ignore_mismatched_sizes=True,
        ).to(self.device)

        # 1. Dataset Generation from OWASP Benchmark, parquet CVEs, and API templates
        raw_samples = generate_cybersecurity_training_corpus(multiplier=10)
        full_dataset = VulnerabilityDataset(raw_samples, tokenizer, max_length=self.config.max_length)

        # Compute positive class weights to balance sparse vulnerability categories
        pos_weights = full_dataset.calculate_pos_weights().to(self.device)

        val_size = int(len(full_dataset) * self.config.val_split)
        train_size = len(full_dataset) - val_size
        train_data, val_data = random_split(
            full_dataset,
            [train_size, val_size],
            generator=torch.Generator().manual_seed(42),
        )

        train_loader = DataLoader(train_data, batch_size=self.config.batch_size, shuffle=True)
        val_loader = DataLoader(val_data, batch_size=self.config.batch_size, shuffle=False)

        vuln_count = sum(1 for _, l in raw_samples if l)
        safe_count = len(raw_samples) - vuln_count
        console.print(
            f"Dataset assembled: [bold green]{len(full_dataset)} total code slices[/bold green] "
            f"({vuln_count} vulnerable, {safe_count} safe controls, {train_size} train, {val_size} val)"
        )

        # 2. Optimization setup: AdamW with Cosine Annealing & Weighted BCE Loss
        optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=self.config.epochs, eta_min=5e-6)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weights)

        total_start = time.perf_counter()
        history: List[Dict[str, float]] = []
        best_f1 = 0.0
        best_threshold = 0.40

        console.print(f"\n[bold green]Beginning GPU Fine-Tuning ({self.config.epochs} Epochs on {self.device})[/bold green]:")

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

            scheduler.step()
            avg_train_loss = round(total_train_loss / len(train_loader), 4)

            # Validation Pass
            model.eval()
            total_val_loss = 0.0
            all_probs: List[torch.Tensor] = []
            all_labels: List[torch.Tensor] = []

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
                    probs = torch.sigmoid(v_outputs.logits)
                    all_probs.append(probs.cpu())
                    all_labels.append(v_labels.cpu())

            avg_val_loss = round(total_val_loss / len(val_loader), 4)
            cat_probs = torch.cat(all_probs, dim=0)
            cat_labels = torch.cat(all_labels, dim=0)

            # Threshold Search: scan candidate thresholds for optimal F1
            epoch_best_f1 = 0.0
            epoch_best_p = 0.0
            epoch_best_r = 0.0
            epoch_best_th = 0.40

            for th in [0.25, 0.30, 0.35, 0.40, 0.45, 0.50]:
                preds = (cat_probs >= th).float()
                tp = ((preds == 1) & (cat_labels == 1)).sum().item()
                fp = ((preds == 1) & (cat_labels == 0)).sum().item()
                fn = ((preds == 0) & (cat_labels == 1)).sum().item()

                p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0

                if f1 > epoch_best_f1:
                    epoch_best_f1 = f1
                    epoch_best_p = p
                    epoch_best_r = r
                    epoch_best_th = th

            # Hamming accuracy (overall multi-label decision accuracy across all labels)
            final_preds = (cat_probs >= epoch_best_th).float()
            hamming_acc = (final_preds == cat_labels).float().mean().item()

            # Top-1 accuracy on vulnerable samples
            vuln_mask = cat_labels.sum(dim=-1) > 0
            if vuln_mask.sum() > 0:
                top1_preds = cat_probs[vuln_mask].argmax(dim=-1)
                top1_labels = cat_labels[vuln_mask].argmax(dim=-1)
                top1_acc = (top1_preds == top1_labels).float().mean().item()
            else:
                top1_acc = 1.0

            duration = round(time.perf_counter() - epoch_start, 2)

            console.print(
                f"  Epoch {epoch}: Train Loss: [cyan]{avg_train_loss}[/cyan] | "
                f"Val Loss: [yellow]{avg_val_loss}[/yellow] | "
                f"Accuracy: [bold white]{round(hamming_acc * 100, 1)}%[/bold white] | "
                f"Top-1: [bold white]{round(top1_acc * 100, 1)}%[/bold white] | "
                f"Precision: [green]{int(epoch_best_p * 100)}%[/green] | "
                f"Recall: [green]{int(epoch_best_r * 100)}%[/green] | "
                f"F1: [bold green]{round(epoch_best_f1, 3)}[/bold green] (th={epoch_best_th}) [{duration}s]"
            )

            history.append({
                "epoch": epoch,
                "train_loss": avg_train_loss,
                "val_loss": avg_val_loss,
                "hamming_accuracy": round(hamming_acc, 4),
                "top1_accuracy": round(top1_acc, 4),
                "precision": round(epoch_best_p, 4),
                "recall": round(epoch_best_r, 4),
                "f1": round(epoch_best_f1, 4),
                "optimal_threshold": epoch_best_th,
            })

            # Checkpoint save on improved F1
            if epoch_best_f1 >= best_f1:
                best_f1 = epoch_best_f1
                best_threshold = epoch_best_th
                model.save_pretrained(out_path)
                tokenizer.save_pretrained(out_path)

        total_time = round(time.perf_counter() - total_start, 2)
        console.print(f"\n[bold green]✓ Training Complete in {total_time}s! Peak F1: {round(best_f1, 3)}[/bold green]")

        # 3. Final Summary Table
        table = Table(title="SecureBERT 2.0 Fine-Tuning Performance Summary", header_style="bold green")
        table.add_column("Epoch", style="cyan")
        table.add_column("Train Loss", justify="right")
        table.add_column("Val Loss", justify="right")
        table.add_column("Hamming Acc", justify="right", style="bold white")
        table.add_column("Top-1 Acc", justify="right", style="bold white")
        table.add_column("Precision", justify="right", style="green")
        table.add_column("Recall", justify="right", style="green")
        table.add_column("F1 Score", justify="right", style="bold green")

        for h in history:
            table.add_row(
                str(h["epoch"]),
                str(h["train_loss"]),
                str(h["val_loss"]),
                f"{round(h['hamming_accuracy'] * 100, 1)}%",
                f"{round(h['top1_accuracy'] * 100, 1)}%",
                f"{int(h['precision'] * 100)}%",
                f"{int(h['recall'] * 100)}%",
                str(h["f1"]),
            )
        console.print(table)

        metadata = {
            "base_model": self.config.model_name,
            "categories": VULN_CATEGORIES,
            "epochs": self.config.epochs,
            "peak_f1": best_f1,
            "optimal_threshold": best_threshold,
            "device": str(self.device),
            "training_time_seconds": total_time,
            "history": history,
        }
        with open(out_path / "training_metadata.json", "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        console.print(f"[bold green]Best model checkpoint deployed to {out_path} (threshold={best_threshold})![/bold green]\n")
        return metadata
