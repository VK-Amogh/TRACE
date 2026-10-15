"""Accelerator resolution for TRACE neural inference.

Centralizes device selection so every engine (SecureBERT, Laya torch,
Laya ONNX) agrees on where to run:

- torch: explicit ``TRACE_DEVICE`` override, else CUDA, else MPS, else CPU.
  ROCm needs no code changes (torch exposes the CUDA API there).
- ONNX Runtime: ``TRACE_ORT_PROVIDERS`` override, else CUDA, CoreML,
  OpenVINO, CPU — filtered by what is actually installed, always ending
  with ``CPUExecutionProvider`` so inference degrades instead of crashing.
  Optional packages: ``onnxruntime-gpu`` (CUDA), ``onnxruntime-openvino``
  (Intel). CoreML ships inside stock onnxruntime on macOS.
- fp16 autocast is enabled only on CUDA (proven there; MPS stays fp32),
  overridable with ``TRACE_DTYPE=fp16|fp32``.

This module must stay dependency-free (stdlib only) so lite installs and
``trace doctor`` can import it without torch or onnxruntime present.
"""

import os
from typing import Dict, List, Optional

ORT_PROVIDER_PRIORITY = (
    "CUDAExecutionProvider",
    "CoreMLExecutionProvider",
    "OpenVINOExecutionProvider",
    "CPUExecutionProvider",
)


def resolve_torch_device(preference: Optional[str] = None) -> str:
    """Pick a torch device: 'cuda', 'mps', or 'cpu' (never raises)."""
    pref = (preference if preference is not None else os.environ.get("TRACE_DEVICE", "auto")).strip().lower()
    if pref in ("cuda", "mps", "cpu"):
        return pref
    try:
        import torch

        if torch.cuda.is_available():
            return "cuda"
        mps_backend = getattr(getattr(torch, "backends", None), "mps", None)
        is_available = getattr(mps_backend, "is_available", None)
        if callable(is_available) and is_available():
            return "mps"
    except Exception:
        pass
    return "cpu"


def use_fp16(device: Optional[str] = None) -> bool:
    """Whether to run inference under fp16 autocast (CUDA only by default)."""
    dtype = os.environ.get("TRACE_DTYPE", "auto").strip().lower()
    if dtype in ("fp32", "float32"):
        return False
    if dtype in ("fp16", "float16"):
        return True
    resolved = device or resolve_torch_device()
    return resolved == "cuda"


def resolve_ort_providers(preference: Optional[str] = None) -> List[str]:
    """Ordered ORT execution providers, always ending with CPU fallback."""
    override = preference if preference is not None else os.environ.get("TRACE_ORT_PROVIDERS", "")
    if override and override.strip():
        wanted = [p.strip() for p in override.split(",") if p.strip()]
        if wanted:
            return wanted if wanted[-1] == "CPUExecutionProvider" else wanted + ["CPUExecutionProvider"]
    try:
        import onnxruntime as ort

        available = set(ort.get_available_providers())
    except Exception:
        return ["CPUExecutionProvider"]
    picked = [p for p in ORT_PROVIDER_PRIORITY if p in available]
    return picked or ["CPUExecutionProvider"]


def describe_accelerators() -> Dict[str, str]:
    """Lightweight status snapshot for `trace doctor` (never loads models)."""
    try:
        import torch

        torch_version = getattr(torch, "__version__", "unknown")
    except Exception:
        torch_version = "not installed"
    device = resolve_torch_device()
    providers = resolve_ort_providers()
    return {
        "torch_device": device,
        "torch_version": torch_version,
        "ort_providers": ",".join(providers),
        "fp16": str(use_fp16(device)),
    }
