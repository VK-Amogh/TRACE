"""Automated model downloader and provisioner for TRACE fine-tuned weights."""

import os
import sys
import logging
import urllib.request
from pathlib import Path
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)

REPO_OWNER = "VK-Amogh"
REPO_NAME = "TRACE"
BRANCH = "main"

MODEL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "securebert-finetuned": {
        "files": {
            "config.json": {
                "url": f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/securebert-finetuned/config.json",
                "min_size": 500,
            },
            "tokenizer.json": {
                "url": f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/securebert-finetuned/tokenizer.json",
                "min_size": 1000000,
            },
            "tokenizer_config.json": {
                "url": f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/securebert-finetuned/tokenizer_config.json",
                "min_size": 200,
            },
            "model.safetensors": {
                "url": f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/securebert-finetuned/model.safetensors",
                "min_size": 100000000,  # ~498 MB
            },
        },
    },
    "laya-finetuned": {
        "files": {
            "laya_metadata.json": {
                "url": f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/laya_metadata.json",
                "min_size": 300,
            },
            "tokenizer.json": {
                "url": f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/tokenizer.json",
                "min_size": 500000,
            },
            "tokenizer_config.json": {
                "url": f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/tokenizer_config.json",
                "min_size": 200,
            },
            "laya_dual_head.onnx": {
                "url": f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/laya_dual_head.onnx",
                "min_size": 50000000,  # ~267 MB
            },
            "laya_dual_head.pt": {
                "url": f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/laya_dual_head.pt",
                "min_size": 50000000,  # ~267 MB
            },
        },
    },
}


def get_default_models_dir() -> Path:
    """Returns the default persistent directory for TRACE models (~/.trace/models)."""
    target = Path.home() / ".trace" / "models"
    target.mkdir(parents=True, exist_ok=True)
    return target


def is_model_installed(model_name: str, candidate_dir: Optional[Path] = None) -> bool:
    """Checks if all required model files are present and valid (not empty or git lfs pointer stubs)."""
    if model_name not in MODEL_REGISTRY:
        return False

    spec = MODEL_REGISTRY[model_name]
    target_dir = candidate_dir or (get_default_models_dir() / model_name)
    if not target_dir.exists():
        return False

    for filename, meta in spec["files"].items():
        file_path = target_dir / filename
        if not file_path.exists():
            return False
        if file_path.stat().st_size < meta["min_size"]:
            return False

    return True


def ensure_model(model_name: str) -> Path:
    """Ensures model is installed locally; downloads missing files from GitHub LFS/Repo if needed."""
    models_dir = get_default_models_dir()
    target_dir = models_dir / model_name
    target_dir.mkdir(parents=True, exist_ok=True)

    if is_model_installed(model_name, target_dir):
        return target_dir

    if model_name not in MODEL_REGISTRY:
        raise ValueError(f"Unknown model: {model_name}")

    spec = MODEL_REGISTRY[model_name]
    print(f"\n\033[38;2;16;185;129m[TRACE Model Hub]\033[0m Downloading fine-tuned {model_name} neural weights...")

    for filename, meta in spec["files"].items():
        file_path = target_dir / filename
        if file_path.exists() and file_path.stat().st_size >= meta["min_size"]:
            continue

        temp_path = target_dir / f"{filename}.tmp"
        url = meta["url"]
        print(f"  \033[38;2;255;158;59m›\033[0m Fetching {filename}...")

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "TRACE-Security-Engine/2.1 (github:VK-Amogh/TRACE)"},
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                total_size = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                block_size = 1024 * 1024  # 1 MB chunk

                with open(temp_path, "wb") as f:
                    while True:
                        chunk = resp.read(block_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            mb_down = downloaded / (1024 * 1024)
                            mb_tot = total_size / (1024 * 1024)
                            sys.stdout.write(f"\r    [{percent:.1f}%] {mb_down:.1f} MB / {mb_tot:.1f} MB")
                            sys.stdout.flush()

            print()
            if temp_path.exists():
                temp_path.replace(file_path)

        except Exception as e:
            if temp_path.exists():
                temp_path.unlink()
            logger.warning(f"Failed to download {filename} from {url}: {e}")
            raise RuntimeError(f"Could not download {filename} for {model_name}: {e}")

    print(f"\033[38;2;16;185;129m✓ Successfully provisioned {model_name}\033[0m\n")
    return target_dir


def ensure_all_models() -> None:
    """Proactively ensures all fine-tuned models are downloaded and verified."""
    for model_name in MODEL_REGISTRY:
        ensure_model(model_name)
