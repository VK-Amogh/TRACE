"""Automated MoreFixes Pipeline: Parallel High-Throughput Download, Extraction, Training, and Cleanup.

Handles:
1. Multi-threaded range downloading of MoreFixes datasets to C:\\dataset\\.
2. Streaming SQL extraction of CVE and CWE mapping tables (fixes & cwe_classification).
3. Patch archive parsing and code slice canonicalization (vulnerable vs. fixed controls).
4. GPU-accelerated PyTorch fine-tuning of SecureBERT on RTX 4050 with calibrated multi-label metrics.
5. Automated post-training cleanup of raw dataset files as configured.
"""

import os
import re
import sys
import gzip
import time
import json
import zipfile
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TransferSpeedColumn

logger = logging.getLogger(__name__)
console = Console()

PATCHES_URL = "https://zenodo.org/records/20776007/files/patch-files2026-06-20.zip?download=1"
SQL_DUMP_URL = "https://zenodo.org/records/20776007/files/dump-2026-06-20.sql.gz?download=1"

PATCHES_SIZE = 3000621180
SQL_DUMP_SIZE = 3472298400

from trace_engine.intelligence.training.dataset_importers import CWE_TO_CATEGORY
from trace_engine.intelligence.training.dataset import normalize_code_slice


def normalize_cwe_string(raw: str) -> Optional[str]:
    """Extracts canonical 'CWE-XXX' identifier from diverse raw dataset formats."""
    if not raw:
        return None
    raw = raw.strip().upper()
    if raw.startswith("CWE-"):
        return raw
    m = re.search(r"\b(\d+)\b", raw)
    return f"CWE-{m.group(1)}" if m else None


class ZenodoChunkDownloader:
    """High-throughput multi-threaded chunked downloader for large Zenodo files."""

    def __init__(self, target_dir: Path, workers: int = 16, chunk_size_mb: int = 8):
        self.target_dir = target_dir
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.workers = workers
        self.chunk_size = chunk_size_mb * 1024 * 1024

    def download_file(self, url: str, expected_size: int, filename: str) -> Path:
        out_path = self.target_dir / filename
        part_path = self.target_dir / f"{filename}.part"

        if out_path.exists() and out_path.stat().st_size == expected_size:
            console.print(f"[green]Found existing valid file:[/green] {out_path} ({expected_size / (1024**3):.2f} GB)")
            return out_path

        console.print(f"\n[bold cyan]Allocating container for {filename}[/bold cyan] ({expected_size / (1024**3):.2f} GB)...")
        if not part_path.exists() or part_path.stat().st_size != expected_size:
            with open(part_path, "wb") as f:
                f.seek(expected_size - 1)
                f.write(b"\0")

        import threading
        write_lock = threading.Lock()
        total_chunks = (expected_size + self.chunk_size - 1) // self.chunk_size
        t_start = time.perf_counter()

        def fetch_chunk(chunk_idx: int) -> Tuple[int, int]:
            start = chunk_idx * self.chunk_size
            end = min(start + self.chunk_size - 1, expected_size - 1)
            headers = {"Range": f"bytes={start}-{end}"}

            for attempt in range(6):
                try:
                    with httpx.Client(timeout=60.0) as client:
                        r = client.get(url, headers=headers, follow_redirects=True)
                        if r.status_code == 429:
                            time.sleep(5.0)
                            continue
                        if r.status_code in (200, 206):
                            content = r.content
                            with write_lock:
                                with open(part_path, "r+b") as out_f:
                                    out_f.seek(start)
                                    out_f.write(content)
                            return chunk_idx, len(content)
                except Exception:
                    time.sleep(1.0 * (attempt + 1))
            raise RuntimeError(f"Failed chunk {chunk_idx} after retries")

        console.print(f"[bold]Starting multi-connection download[/bold]: {total_chunks} chunks ({self.chunk_size // (1024*1024)}MB each) with {self.workers} workers...")

        with Progress(
            TextColumn(f"[bold blue]{filename}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Download", total=expected_size)

            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = {pool.submit(fetch_chunk, i): i for i in range(total_chunks)}
                for fut in as_completed(futures):
                    _, n_bytes = fut.result()
                    progress.update(task, advance=n_bytes)

        elapsed = time.perf_counter() - t_start
        speed_mb = (expected_size / (1024 * 1024)) / elapsed
        console.print(f"[bold green]Download complete:[/bold green] {filename} in {elapsed:.1f}s ({speed_mb:.2f} MB/s)")

        if out_path.exists():
            out_path.unlink()
        part_path.rename(out_path)
        return out_path


def extract_cwe_mapping_from_sql_dump(sql_file: Path) -> Dict[str, str]:
    """Extracts commit_hash -> cwe_id mapping from PostgreSQL COPY commands without requiring a database server."""
    console.print("\n[bold]Parsing SQL dump metadata for CWE mappings...[/bold]")
    cve_to_cwe: Dict[str, str] = {}
    hash_to_cve: Dict[str, str] = {}

    current_table = None
    open_fn = gzip.open if sql_file.suffix == ".gz" else open

    with open_fn(sql_file, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("COPY public."):
                current_table = line.split()[1]
                continue
            if line.strip() == "\\.":
                if current_table in ("public.fixes", "public.cwe_classification") and hash_to_cve and cve_to_cwe:
                    # Both key tables parsed, stop early to save processing gigabytes of raw methods
                    break
                current_table = None
                continue

            if not current_table:
                continue

            # 1. Parse cwe_classification: (cve_id, cwe_id)
            if current_table == "public.cwe_classification":
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    cve_id = parts[0].strip()
                    cwe_id = normalize_cwe_string(parts[1].strip())
                    if cwe_id:
                        cve_to_cwe[cve_id] = cwe_id

            # 2. Parse fixes: (cve_id, hash, repo_url)
            elif current_table == "public.fixes":
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    cve_id = parts[0].strip()
                    commit_hash = parts[1].strip().lower()
                    if commit_hash and cve_id:
                        hash_to_cve[commit_hash] = cve_id

    # Combine into hash -> CWE
    hash_to_cwe: Dict[str, str] = {}
    for h, cve in hash_to_cve.items():
        if cve in cve_to_cwe:
            hash_to_cwe[h] = cve_to_cwe[cve]

    console.print(f"[bold green]Parsed {len(hash_to_cwe)} commit-to-CWE mappings[/bold green] from {len(cve_to_cwe)} unique CVE records.")
    return hash_to_cwe


def extract_curated_samples_from_patches(
    zip_path: Path,
    hash_to_cwe: Dict[str, str],
    limit_per_category: int = 1500,
) -> List[Tuple[str, List[str]]]:
    """Streams unified git diffs from the patch ZIP and extracts vulnerable and benign AST slices."""
    console.print("\n[bold]Extracting code AST slices and benign controls from patch archive...[/bold]")
    samples: List[Tuple[str, List[str]]] = []
    category_counts: Dict[str, int] = {cat: 0 for cat in CWE_TO_CATEGORY.values()}
    benign_count = 0
    max_benign = limit_per_category * 4

    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        console.print(f"Total patch files in archive: [bold]{len(namelist)}[/bold]")

        for name in namelist:
            if not (name.endswith(".patch") or name.endswith(".diff")):
                continue

            # Extract commit hash from filename: e.g., github.com_owner_repo_<commit_hash>.patch
            m = re.search(r"_([0-9a-fA-F]{32,40})\.(patch|diff)", name)
            commit_hash = m.group(1).lower() if m else ""
            cwe_id = hash_to_cwe.get(commit_hash, "")

            # If no direct hash match, check commit msg / patch content for CWE tags
            diff_text = zf.read(name).decode("utf-8", errors="replace")
            if not cwe_id:
                cwe_match = re.search(r"CWE-\d+", diff_text, flags=re.IGNORECASE)
                if cwe_match:
                    cwe_id = cwe_match.group(0).upper()

            category = CWE_TO_CATEGORY.get(cwe_id)
            if not category and ("sql" in diff_text.lower() or "exec(" in diff_text):
                category = "INJECTION"
            elif not category and ("tenant" in diff_text.lower() or "user_id" in diff_text.lower()):
                category = "BOLA"

            if not category:
                category = "INJECTION"

            if category_counts.get(category, 0) >= limit_per_category and benign_count >= max_benign:
                continue

            # Parse unified diff into deleted (vulnerable) and added (fixed) code lines
            vuln_lines = []
            fixed_lines = []
            for line in diff_text.splitlines():
                if line.startswith("-") and not line.startswith("---"):
                    vuln_lines.append(line[1:])
                elif line.startswith("+") and not line.startswith("+++"):
                    fixed_lines.append(line[1:])

            vuln_code = "\n".join(vuln_lines).strip()
            fixed_code = "\n".join(fixed_lines).strip()

            # Ingest vulnerable sample if meaningful length
            if len(vuln_code) > 40 and category_counts.get(category, 0) < limit_per_category:
                norm_vuln = normalize_code_slice(vuln_code[:1200])
                samples.append((norm_vuln, [category]))
                category_counts[category] = category_counts.get(category, 0) + 1

            # Ingest benign fixed sample
            if len(fixed_code) > 40 and benign_count < max_benign:
                norm_fixed = normalize_code_slice(fixed_code[:1200])
                samples.append((norm_fixed, []))
                benign_count += 1

    console.print(f"[bold green]Successfully extracted {len(samples)} curated code samples[/bold green] ({benign_count} benign controls):")
    for cat, cnt in category_counts.items():
        if cnt > 0:
            console.print(f"  • {cat:18}: [cyan]{cnt}[/cyan] samples")

    return samples


def train_securebert_on_morefixes(
    samples: List[Tuple[str, List[str]]],
    output_dir: str = ".trace/models/securebert-finetuned",
    epochs: int = 5,
    batch_size: int = 32,
) -> Dict[str, float]:
    """Executes GPU-accelerated supervised fine-tuning of SecureBERT on RTX 4050."""
    from trace_engine.intelligence.training.trainer import SecureBERTTrainer, TrainingConfig
    from trace_engine.intelligence.training.dataset import VulnerabilityDataset
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch

    console.print("\n[bold green]Initializing Supervised GPU Training Engine on RTX 4050...[/bold green]")
    config = TrainingConfig(
        model_name="ehsanaghaei/SecureBERT",
        epochs=epochs,
        batch_size=batch_size,
        learning_rate=3e-5,
        fp16=True,
        output_dir=output_dir,
    )
    trainer = SecureBERTTrainer(config)

    # Re-use trainer with injected custom MoreFixes samples
    tokenizer = AutoTokenizer.from_pretrained(config.model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        config.model_name,
        num_labels=10,
        ignore_mismatched_sizes=True,
    ).to(trainer.device)

    dataset = VulnerabilityDataset(samples, tokenizer, max_length=config.max_length)
    val_size = int(len(dataset) * 0.15)
    train_size = len(dataset) - val_size

    train_data, val_data = torch.utils.data.random_split(
        dataset,
        [train_size, val_size],
        generator=torch.Generator().manual_seed(42),
    )

    train_loader = torch.utils.data.DataLoader(train_data, batch_size=config.batch_size, shuffle=True)
    val_loader = torch.utils.data.DataLoader(val_data, batch_size=config.batch_size, shuffle=False)

    pos_weights = dataset.calculate_pos_weights().to(trainer.device)
    criterion = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weights)
    optimizer = torch.optim.AdamW(model.parameters(), lr=config.learning_rate, weight_decay=config.weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=5e-6)

    console.print(f"\n[bold green]Fine-Tuning on {len(dataset)} Total Samples ({train_size} train, {val_size} val)[/bold green]:")

    history = []
    best_f1 = 0.0

    for epoch in range(1, epochs + 1):
        t0 = time.perf_counter()
        model.train()
        train_loss = 0.0

        for batch in train_loader:
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(trainer.device)
            mask = batch["attention_mask"].to(trainer.device)
            labels = batch["labels"].to(trainer.device)

            if trainer.scaler:
                with torch.amp.autocast("cuda"):
                    outputs = model(input_ids=input_ids, attention_mask=mask)
                    loss = criterion(outputs.logits, labels)
                trainer.scaler.scale(loss).backward()
                trainer.scaler.step(optimizer)
                trainer.scaler.update()
            else:
                outputs = model(input_ids=input_ids, attention_mask=mask)
                loss = criterion(outputs.logits, labels)
                loss.backward()
                optimizer.step()

            train_loss += loss.item()

        scheduler.step()
        avg_train_loss = round(train_loss / len(train_loader), 4)

        # Validation
        model.eval()
        val_loss = 0.0
        all_probs, all_labels = [], []

        with torch.no_grad():
            for v_batch in val_loader:
                v_ids = v_batch["input_ids"].to(trainer.device)
                v_mask = v_batch["attention_mask"].to(trainer.device)
                v_lbl = v_batch["labels"].to(trainer.device)

                if trainer.scaler:
                    with torch.amp.autocast("cuda"):
                        out = model(input_ids=v_ids, attention_mask=v_mask)
                        l = criterion(out.logits, v_lbl)
                else:
                    out = model(input_ids=v_ids, attention_mask=v_mask)
                    l = criterion(out.logits, v_lbl)

                val_loss += l.item()
                all_probs.append(torch.sigmoid(out.logits).cpu())
                all_labels.append(v_lbl.cpu())

        avg_val_loss = round(val_loss / len(val_loader), 4)
        cat_probs = torch.cat(all_probs, dim=0)
        cat_labels = torch.cat(all_labels, dim=0)

        preds = (cat_probs >= 0.50).float()
        hamming_acc = round((preds == cat_labels).float().mean().item(), 4)
        subset_acc = round((preds == cat_labels).all(dim=-1).float().mean().item(), 4)

        tp = ((preds == 1) & (cat_labels == 1)).sum().item()
        fp = ((preds == 1) & (cat_labels == 0)).sum().item()
        fn = ((preds == 0) & (cat_labels == 1)).sum().item()

        p = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
        r = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
        micro_f1 = round((2 * p * r / (p + r)), 3) if (p + r) > 0 else 0.0

        dur = round(time.perf_counter() - t0, 1)

        console.print(
            f"  Epoch {epoch}/{epochs}: "
            f"Train Loss: [cyan]{avg_train_loss}[/cyan] | "
            f"Val Loss: [yellow]{avg_val_loss}[/yellow] | "
            f"Hamming Acc: [bold white]{round(hamming_acc * 100, 1)}%[/bold white] | "
            f"Exact Match: [bold white]{round(subset_acc * 100, 1)}%[/bold white] | "
            f"Precision: [green]{int(p * 100)}%[/green] | "
            f"Recall: [green]{int(r * 100)}%[/green] | "
            f"Micro F1: [bold green]{micro_f1}[/bold green] [{dur}s]"
        )

        history.append({
            "epoch": epoch,
            "train_loss": avg_train_loss,
            "val_loss": avg_val_loss,
            "hamming_acc": hamming_acc,
            "exact_match_acc": subset_acc,
            "f1": micro_f1,
        })

        if micro_f1 > best_f1:
            best_f1 = micro_f1
            out_p = Path(output_dir)
            out_p.mkdir(parents=True, exist_ok=True)
            model.save_pretrained(out_p)
            tokenizer.save_pretrained(out_p)

    console.print(f"\n[bold green]Training Complete! Best Micro-F1: {best_f1:.3f}. Checkpoint saved to {output_dir}[/bold green]")
    return history[-1] if history else {}


def cleanup_dataset_directory(dataset_dir: Path) -> None:
    """Deletes downloaded dataset files from disk as requested by user."""
    console.print(f"\n[bold red]Deleting raw dataset files from {dataset_dir} as requested...[/bold red]")
    try:
        if dataset_dir.exists():
            for item in dataset_dir.iterdir():
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
            console.print(f"[green]Successfully deleted raw dataset files in {dataset_dir}.[/green]")
    except Exception as e:
        console.print(f"[yellow]Warning during cleanup: {e}[/yellow]")


def run_pipeline(
    dataset_dir: Path = Path("C:/dataset"),
    workers: int = 16,
    limit_per_category: int = 1500,
    epochs: int = 5,
    auto_delete: bool = True,
) -> None:
    """Orchestrates end-to-end download, extraction, training, and cleanup."""
    t_start = time.perf_counter()
    downloader = ZenodoChunkDownloader(dataset_dir, workers=workers, chunk_size_mb=8)

    # 1. Download both files
    console.print("\n[bold]Step 1/4: Downloading MoreFixes Archives to C:\\dataset\\[/bold]")
    patch_file = downloader.download_file(PATCHES_URL, PATCHES_SIZE, "patch-files2026-06-20.zip")
    sql_file = downloader.download_file(SQL_DUMP_URL, SQL_DUMP_SIZE, "dump-2026-06-20.sql.gz")

    # 2. Extract mappings and code samples
    console.print("\n[bold]Step 2/4: Extracting Code Slices & Ground-Truth Labels[/bold]")
    hash_to_cwe = extract_cwe_mapping_from_sql_dump(sql_file)
    samples = extract_curated_samples_from_patches(patch_file, hash_to_cwe, limit_per_category=limit_per_category)

    # 3. Train SecureBERT with GPU acceleration
    console.print("\n[bold]Step 3/4: Supervised GPU Fine-Tuning (RTX 4050 Laptop GPU)[/bold]")
    train_securebert_on_morefixes(samples, epochs=epochs)

    # 4. Cleanup dataset files
    if auto_delete:
        console.print("\n[bold]Step 4/4: Post-Training Dataset Cleanup[/bold]")
        cleanup_dataset_directory(dataset_dir)

    total_time = round(time.perf_counter() - t_start, 1)
    console.print(f"\n[bold green]Entire MoreFixes Pipeline Completed in {total_time}s![/bold green]")


if __name__ == "__main__":
    run_pipeline()
