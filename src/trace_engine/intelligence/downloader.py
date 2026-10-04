"""Automated model downloader, verification gate, and provisioner for TRACE fine-tuned weights."""

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
                "urls": [
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/models/securebert-finetuned/config.json",
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/securebert-finetuned/config.json",
                ],
                "min_size": 500,
            },
            "tokenizer.json": {
                "urls": [
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/models/securebert-finetuned/tokenizer.json",
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/securebert-finetuned/tokenizer.json",
                ],
                "min_size": 1000000,
            },
            "tokenizer_config.json": {
                "urls": [
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/models/securebert-finetuned/tokenizer_config.json",
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/securebert-finetuned/tokenizer_config.json",
                ],
                "min_size": 200,
            },
            "model.safetensors": {
                "urls": [
                    f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/models/securebert-finetuned/model.safetensors",
                    f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/securebert-finetuned/model.safetensors",
                ],
                "min_size": 100000000,  # ~498 MB
            },
        },
    },
    "laya-finetuned": {
        "files": {
            "laya_metadata.json": {
                "urls": [
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/models/laya-finetuned/laya_metadata.json",
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/laya_metadata.json",
                ],
                "min_size": 300,
            },
            "tokenizer.json": {
                "urls": [
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/models/laya-finetuned/tokenizer.json",
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/tokenizer.json",
                ],
                "min_size": 500000,
            },
            "tokenizer_config.json": {
                "urls": [
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/models/laya-finetuned/tokenizer_config.json",
                    f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/tokenizer_config.json",
                ],
                "min_size": 200,
            },
            "laya_dual_head.onnx": {
                "urls": [
                    f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/models/laya-finetuned/laya_dual_head.onnx",
                    f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/laya_dual_head.onnx",
                ],
                "min_size": 50000000,  # ~267 MB
            },
            "laya_dual_head.pt": {
                "urls": [
                    f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/models/laya-finetuned/laya_dual_head.pt",
                    f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/.trace/models/laya-finetuned/laya_dual_head.pt",
                ],
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


def is_environment_ready() -> bool:
    """Checks if both fine-tuned SecureBERT 2.0 and Laya System 1 models are installed and valid."""
    repo_root = Path(__file__).resolve().parents[4]
    candidate_roots = [
        Path.home() / ".trace" / "models",
        Path("models"),
        Path(".trace/models"),
        repo_root / "models",
        repo_root / ".trace/models",
        Path("D:/Startup/TRACE/models"),
        Path("D:/Startup/TRACE/.trace/models"),
    ]

    sb_ok = False
    laya_ok = False

    for r in candidate_roots:
        if not sb_ok and is_model_installed("securebert-finetuned", r / "securebert-finetuned"):
            sb_ok = True
        if not laya_ok and is_model_installed("laya-finetuned", r / "laya-finetuned"):
            laya_ok = True
        if sb_ok and laya_ok:
            return True

    return False


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
        urls = meta.get("urls", [])
        print(f"  \033[38;2;255;158;59m›\033[0m Fetching {filename}...")

        success = False
        last_error = None
        for url in urls:
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
                success = True
                break

            except Exception as e:
                last_error = e
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except Exception:
                        pass
                continue

        if not success:
            logger.warning(f"Failed to download {filename}: {last_error}")
            raise RuntimeError(f"Could not download {filename} for {model_name}: {last_error}")

    print(f"\033[38;2;16;185;129m✓ Successfully provisioned {model_name}\033[0m\n")
    return target_dir


def ensure_all_models() -> None:
    """Proactively ensures all fine-tuned models are downloaded and verified."""
    for model_name in MODEL_REGISTRY:
        ensure_model(model_name)


def prompt_and_bootstrap_models(interactive: bool = True) -> bool:
    """Interactive gate: checks if models are installed, prompts user to agree and downloads them."""
    if is_environment_ready():
        return True

    CYAN = "\033[38;2;56;189;248m"
    GREEN = "\033[38;2;16;185;129m"
    ORANGE = "\033[38;2;255;158;59m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    print(f"\n  {GREEN}┌{'─' * 74}┐{RESET}")
  
    print(f"  {GREEN}│{RESET}  {BOLD}TRACE Neural Intelligence Engine — First-Time Environment Setup{RESET}        {GREEN}│{RESET}")
    print(f"  {GREEN}├{'─' * 74}┤{RESET}")
    print(f"  {GREEN}│{RESET}  TRACE requires fine-tuned neural models for autonomous AST attack-path      {GREEN}│{RESET}")
    print(f"  {GREEN}│{RESET}  correlation and vulnerability verification:                                {GREEN}│{RESET}")
    print(f"  {GREEN}│{RESET}   • {CYAN}SecureBERT 2.0{RESET}  (Fine-Tuned OWASP API Vulnerability Classifier)          {GREEN}│{RESET}")
    print(f"  {GREEN}│{RESET}   • {CYAN}Laya System 1{RESET}   (Non-Autoregressive Fast Decision & Priority Router)     {GREEN}│{RESET}")
    print(f"  {GREEN}│{RESET}                                                                          {GREEN}│{RESET}")
    print(f"  {GREEN}│{RESET}  {DIM}Dedicated Location : ~/.trace/models/{RESET}                                     {GREEN}│{RESET}")
    print(f"  {GREEN}│{RESET}  {DIM}Source             : Official TRACE Git LFS Hub (github:VK-Amogh/TRACE){RESET}   {GREEN}│{RESET}")
    print(f"  {GREEN}└{'─' * 74}┘{RESET}\n")

    if not interactive or not sys.stdin.isatty():
        print(f"  {ORANGE}[!] Non-interactive environment detected. Run 'trace setup-models' to install.{RESET}\n")
        return False

    try:
        ans = input(f"  {ORANGE}›{RESET} {BOLD}Download and configure fine-tuned neural models now? (y/n) [y]:{RESET} ").strip().lower()
        if ans in ("", "y", "yes"):
            ensure_all_models()
            print(f"  {GREEN}✓ TRACE Neural Intelligence Engine initialized successfully.{RESET}\n")
            return True
        else:
            print(f"\n  {ORANGE}[!] TRACE setup cancelled.{RESET}")
            print(f"  {DIM}Fine-tuned neural intelligence models are required to perform security audits.{RESET}")
            print(f"  {DIM}Run 'trace setup-models' at any time to configure the engine.{RESET}\n")
            return False
    except (KeyboardInterrupt, EOFError):
        print(f"\n  {ORANGE}[!] Cancelled.{RESET}\n")
        return False
