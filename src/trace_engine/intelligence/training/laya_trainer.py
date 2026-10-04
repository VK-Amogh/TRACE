"""Laya System 1 Decision & Routing Fine-Tuning Engine.

Implements PyTorch-accelerated fine-tuning for Laya's non-autoregressive decision model:
- Dual-head sequence classification:
  Head 1: Endpoint Priority (critical, high, medium, low)
  Head 2: Primary Testpack Selection (bola, bfla, authentication, ssrf, injection, mass_assignment, none)
- Early stopping with validation patience
- Multi-framework training corpus mapping APM topologies to ground-truth decisions
"""

import os
import time
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split
from transformers import AutoTokenizer, AutoModel

import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logger = logging.getLogger(__name__)
console = Console(force_terminal=True, legacy_windows=False)

PRIORITY_LABELS = ["critical", "high", "medium", "low"]
TESTPACK_LABELS = ["bola", "bfla", "authentication", "ssrf", "injection", "mass_assignment", "none"]


class LayaTrainingSample(BaseModel):
    """Training tuple mapping endpoint APM state to decision targets."""
    endpoint_state: str
    priority_level: str
    primary_testpack: str


def generate_laya_training_corpus() -> List[LayaTrainingSample]:
    """Generates synthetic and mapped training data from multi-framework APM topologies."""
    samples: List[LayaTrainingSample] = []

    # 1. BOLA / IDOR Patterns
    bola_endpoints = [
        ("GET /api/v1/orders/{id}", "id", False, True, False, True),
        ("GET /api/v2/tenants/{tenant_id}/vaults/{vault_id}", "vault_id", True, True, False, True),
        ("GET /api/v1/users/{userId}/documents/{docId}", "docId", False, True, False, True),
        ("POST /api/v1/patients/{patientId}/export", "patientId", False, True, False, True),
        ("GET /api/v1/go/vault/{id}", "id", False, True, False, True),
    ]
    for method_path, param, auth, db, ext, sens in bola_endpoints:
        state = (
            f"Endpoint: {method_path}\n"
            f"Auth Required: {auth}, Roles: []\n"
            f"Parameters: ['{param}']\n"
            f"Database Access: {db}, Outbound Network: {ext}\n"
            f"State Changing: {'POST' in method_path}, Sensitive Data: {sens}\n"
            f"APM Path Context: Sinks: 1 database sink detected without tenant constraint"
        )
        samples.append(LayaTrainingSample(
            endpoint_state=state,
            priority_level="critical" if not auth else "high",
            primary_testpack="bola"
        ))

    # 2. Injection Patterns (SQLi / Command / Timing)
    injection_endpoints = [
        ("POST /api/v1/analytics/query", "filter", True, True, False, False),
        ("POST /api/v1/go/query", "query", False, True, False, False),
        ("GET /api/v1/products/search", "q", False, True, False, False),
        ("POST /api/v1/system/backup", "target_path", True, False, False, False),
        ("POST /api/v1/users/lookup", "username", False, True, False, False),
    ]
    for method_path, param, auth, db, ext, sens in injection_endpoints:
        state = (
            f"Endpoint: {method_path}\n"
            f"Auth Required: {auth}, Roles: []\n"
            f"Parameters: ['{param}']\n"
            f"Database Access: {db}, Outbound Network: {ext}\n"
            f"State Changing: {'POST' in method_path}, Sensitive Data: {sens}\n"
            f"APM Path Context: Sinks: Dynamic string formatting query execute sink detected"
        )
        samples.append(LayaTrainingSample(
            endpoint_state=state,
            priority_level="critical",
            primary_testpack="injection"
        ))

    # 3. SSRF Patterns
    ssrf_endpoints = [
        ("POST /api/v1/integrations/webhook/dispatch", "webhook_url", True, False, True, False),
        ("POST /api/v1/fetch/avatar", "image_url", False, False, True, False),
        ("GET /api/v2/proxy/resource", "target", False, False, True, False),
        ("POST /api/v1/reports/pdf/render", "callback_url", True, False, True, False),
    ]
    for method_path, param, auth, db, ext, sens in ssrf_endpoints:
        state = (
            f"Endpoint: {method_path}\n"
            f"Auth Required: {auth}, Roles: []\n"
            f"Parameters: ['{param}']\n"
            f"Database Access: {db}, Outbound Network: {ext}\n"
            f"State Changing: {'POST' in method_path}, Sensitive Data: {sens}\n"
            f"APM Path Context: Sinks: External HTTP client egress dispatch sink detected"
        )
        samples.append(LayaTrainingSample(
            endpoint_state=state,
            priority_level="critical" if not auth else "high",
            primary_testpack="ssrf"
        ))

    # 4. BFLA Patterns
    bfla_endpoints = [
        ("POST /api/v1/admin/reset_metrics", "", False, False, False, True),
        ("DELETE /api/v2/admin/users/{id}", "id", False, True, False, True),
        ("POST /api/v1/admin/database/purge", "", False, True, False, True),
        ("PUT /api/v1/admin/tenants/{id}/elevate", "id", False, True, False, True),
    ]
    for method_path, param, auth, db, ext, sens in bfla_endpoints:
        state = (
            f"Endpoint: {method_path}\n"
            f"Auth Required: {auth}, Roles: ['admin']\n"
            f"Parameters: ['{param}']\n"
            f"Database Access: {db}, Outbound Network: {ext}\n"
            f"State Changing: True, Sensitive Data: {sens}\n"
            f"APM Path Context: Sinks: Administrative control sink lacking explicit role verification"
        )
        samples.append(LayaTrainingSample(
            endpoint_state=state,
            priority_level="critical",
            primary_testpack="bfla"
        ))

    # 5. Safe / Low Priority Endpoints
    safe_endpoints = [
        ("GET /health", "", False, False, False, False),
        ("GET /static/styles.css", "", False, False, False, False),
        ("GET /favicon.ico", "", False, False, False, False),
        ("GET /api/v1/public/ping", "", False, False, False, False),
        ("GET /docs", "", False, False, False, False),
    ]
    for method_path, param, auth, db, ext, sens in safe_endpoints:
        state = (
            f"Endpoint: {method_path}\n"
            f"Auth Required: {auth}, Roles: []\n"
            f"Parameters: []\n"
            f"Database Access: {db}, Outbound Network: {ext}\n"
            f"State Changing: False, Sensitive Data: {sens}\n"
            f"APM Path Context: No direct sensitive sink"
        )
        samples.append(LayaTrainingSample(
            endpoint_state=state,
            priority_level="low",
            primary_testpack="none"
        ))

    # Multiply dataset with minor variations to create robust batch training sets
    augmented_samples: List[LayaTrainingSample] = []
    for s in samples:
        for suffix in ["", " (version 2)", " (microservice proxy)", " (grpc gateway)"]:
            augmented_samples.append(LayaTrainingSample(
                endpoint_state=s.endpoint_state + suffix,
                priority_level=s.priority_level,
                primary_testpack=s.primary_testpack
            ))

    return augmented_samples


class LayaDataset(Dataset):
    """PyTorch Dataset for Laya decision states."""

    def __init__(self, samples: List[LayaTrainingSample], tokenizer: Any, max_length: int = 128):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        sample = self.samples[idx]
        enc = self.tokenizer(
            sample.endpoint_state,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        prio_idx = PRIORITY_LABELS.index(sample.priority_level) if sample.priority_level in PRIORITY_LABELS else 2
        pack_idx = TESTPACK_LABELS.index(sample.primary_testpack) if sample.primary_testpack in TESTPACK_LABELS else 6

        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "priority_label": torch.tensor(prio_idx, dtype=torch.long),
            "testpack_label": torch.tensor(pack_idx, dtype=torch.long),
        }


class LayaDualHeadModel(nn.Module):
    """Fast non-autoregressive encoder with dual decision heads for Priority & Test Selection."""

    def __init__(self, base_model_name: str = "distilbert/distilbert-base-uncased"):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(base_model_name)
        hidden_size = self.encoder.config.hidden_size

        # Head 1: Priority Classifier (4 classes)
        self.priority_head = nn.Sequential(
            nn.Dropout(0.1),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Linear(hidden_size // 2, len(PRIORITY_LABELS)),
        )

        # Head 2: Test Selection Classifier (7 classes)
        self.testpack_head = nn.Sequential(
            nn.Dropout(0.1),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Linear(hidden_size // 2, len(TESTPACK_LABELS)),
        )

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        pooled = outputs.last_hidden_state[:, 0, :]  # CLS token representation

        prio_logits = self.priority_head(pooled)
        pack_logits = self.testpack_head(pooled)
        return prio_logits, pack_logits


class LayaTrainer:
    """Fine-tuning engine for Laya System 1 decision router."""

    def __init__(
        self,
        base_model_name: str = "distilbert/distilbert-base-uncased",
        output_dir: str = ".trace/models/laya-finetuned",
        epochs: int = 5,
        batch_size: int = 16,
        learning_rate: float = 5e-5,
        early_stopping: bool = True,
        patience: int = 2,
    ):
        self.base_model_name = base_model_name
        self.output_dir = Path(output_dir)
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.early_stopping = early_stopping
        self.patience = patience
        self.device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    def train(self) -> Dict[str, Any]:
        """Executes Laya fine-tuning loop with validation metrics and early stopping."""
        console.print(f"\n[bold green]Initializing Laya System 1 Fine-Tuning Engine[/bold green]")
        console.print(f"  • Device: [bold white]{self.device}[/bold white]")
        console.print(f"  • Target Directory: [white]{self.output_dir}[/white]")
        console.print(f"  • Strategy: Dual-head Multi-Task Cross-Entropy with Early Stopping (patience={self.patience})")

        tokenizer = AutoTokenizer.from_pretrained(self.base_model_name)
        model = LayaDualHeadModel(base_model_name=self.base_model_name).to(self.device)

        corpus = generate_laya_training_corpus()
        dataset = LayaDataset(corpus, tokenizer)

        val_size = max(1, int(len(dataset) * 0.2))
        train_size = len(dataset) - val_size
        train_ds, val_ds = random_split(dataset, [train_size, val_size])

        train_loader = DataLoader(train_ds, batch_size=self.batch_size, shuffle=True)
        val_loader = DataLoader(val_ds, batch_size=self.batch_size, shuffle=False)

        optimizer = torch.optim.AdamW(model.parameters(), lr=self.learning_rate, weight_decay=0.01)
        criterion = nn.CrossEntropyLoss()

        best_val_loss = float("inf")
        stagnant_epochs = 0
        scorecard = []

        for epoch in range(1, self.epochs + 1):
            model.train()
            train_loss = 0.0

            for batch in train_loader:
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                prio_labels = batch["priority_label"].to(self.device)
                pack_labels = batch["testpack_label"].to(self.device)

                optimizer.zero_grad()
                prio_logits, pack_logits = model(input_ids, attention_mask)

                loss_prio = criterion(prio_logits, prio_labels)
                loss_pack = criterion(pack_logits, pack_labels)
                total_loss = loss_prio + loss_pack

                total_loss.backward()
                optimizer.step()
                train_loss += total_loss.item()

            train_loss /= len(train_loader)

            # Evaluation
            model.eval()
            val_loss = 0.0
            correct_prio = 0
            correct_pack = 0
            total_eval = 0

            with torch.no_grad():
                for batch in val_loader:
                    input_ids = batch["input_ids"].to(self.device)
                    attention_mask = batch["attention_mask"].to(self.device)
                    prio_labels = batch["priority_label"].to(self.device)
                    pack_labels = batch["testpack_label"].to(self.device)

                    prio_logits, pack_logits = model(input_ids, attention_mask)
                    loss_prio = criterion(prio_logits, prio_labels)
                    loss_pack = criterion(pack_logits, pack_labels)
                    val_loss += (loss_prio + loss_pack).item()

                    prio_preds = torch.argmax(prio_logits, dim=-1)
                    pack_preds = torch.argmax(pack_logits, dim=-1)

                    correct_prio += (prio_preds == prio_labels).sum().item()
                    correct_pack += (pack_preds == pack_labels).sum().item()
                    total_eval += prio_labels.size(0)

            val_loss /= len(val_loader)
            prio_acc = (correct_prio / total_eval) * 100 if total_eval > 0 else 0.0
            pack_acc = (correct_pack / total_eval) * 100 if total_eval > 0 else 0.0

            console.print(
                f"  Epoch {epoch}/{self.epochs} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | "
                f"Priority Acc: [bold green]{prio_acc:.1f}%[/bold green] | Testpack Acc: [bold green]{pack_acc:.1f}%[/bold green]"
            )

            scorecard.append({
                "epoch": epoch,
                "train_loss": train_loss,
                "val_loss": val_loss,
                "priority_acc": prio_acc,
                "testpack_acc": pack_acc,
            })

            # Checkpoint & Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                stagnant_epochs = 0
                self.output_dir.mkdir(parents=True, exist_ok=True)
                torch.save(model.state_dict(), self.output_dir / "laya_dual_head.pt")
                tokenizer.save_pretrained(self.output_dir)
                (self.output_dir / "laya_metadata.json").write_text(
                    json.dumps({
                        "base_model": self.base_model_name,
                        "priority_labels": PRIORITY_LABELS,
                        "testpack_labels": TESTPACK_LABELS,
                        "best_val_loss": best_val_loss,
                        "prio_acc": prio_acc,
                        "pack_acc": pack_acc,
                    }, indent=2)
                )
            else:
                stagnant_epochs += 1
                if self.early_stopping and stagnant_epochs >= self.patience:
                    console.print(f"  [bold yellow]Early stopping triggered at epoch {epoch}[/bold yellow] (patience={self.patience})")
                    break

        console.print(f"\n[bold green]✓ Laya Fine-Tuning Complete[/bold green]: Saved checkpoint to [white]{self.output_dir}[/white]\n")
        return {"best_val_loss": best_val_loss, "epochs_trained": len(scorecard), "scorecard": scorecard}
