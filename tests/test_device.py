"""Unit tests for accelerator resolution (mocked: no GPU or torch required)."""

import sys
import types

from trace_engine.intelligence import device as device_mod
from trace_engine.intelligence.device import (
    describe_accelerators,
    resolve_ort_providers,
    resolve_torch_device,
    use_fp16,
)


def _fake_torch(cuda_available=False, mps_available=False):
    """Build a minimal fake torch module for resolver tests."""
    mod = types.ModuleType("torch")
    mod.__version__ = "fake"

    class _Cuda:
        @staticmethod
        def is_available():
            return cuda_available

    mod.cuda = _Cuda()

    class _Mps:
        @staticmethod
        def is_available():
            return mps_available

    mod.backends = types.SimpleNamespace(mps=_Mps())
    return mod


def _fake_ort(providers):
    mod = types.ModuleType("onnxruntime")

    def get_available_providers():
        return list(providers)

    mod.get_available_providers = get_available_providers
    return mod


def test_resolve_torch_prefers_cuda(monkeypatch):
    monkeypatch.setitem(sys.modules, "torch", _fake_torch(cuda_available=True, mps_available=True))
    monkeypatch.delenv("TRACE_DEVICE", raising=False)
    assert resolve_torch_device() == "cuda"


def test_resolve_torch_falls_back_to_mps(monkeypatch):
    monkeypatch.setitem(sys.modules, "torch", _fake_torch(cuda_available=False, mps_available=True))
    monkeypatch.delenv("TRACE_DEVICE", raising=False)
    assert resolve_torch_device() == "mps"


def test_resolve_torch_falls_back_to_cpu_without_torch(monkeypatch):
    monkeypatch.setitem(sys.modules, "torch", None)
    monkeypatch.delenv("TRACE_DEVICE", raising=False)
    assert resolve_torch_device() == "cpu"


def test_resolve_torch_env_override(monkeypatch):
    monkeypatch.setitem(sys.modules, "torch", _fake_torch(cuda_available=True))
    monkeypatch.setenv("TRACE_DEVICE", "cpu")
    assert resolve_torch_device() == "cpu"
    monkeypatch.setenv("TRACE_DEVICE", "mps")
    assert resolve_torch_device() == "mps"


def test_resolve_ort_orders_and_falls_back(monkeypatch):
    monkeypatch.setitem(
        sys.modules, "onnxruntime", _fake_ort(["CPUExecutionProvider", "CUDAExecutionProvider"])
    )
    monkeypatch.delenv("TRACE_ORT_PROVIDERS", raising=False)
    assert resolve_ort_providers() == ["CUDAExecutionProvider", "CPUExecutionProvider"]


def test_resolve_ort_cpu_only_when_nothing_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "onnxruntime", None)
    monkeypatch.delenv("TRACE_ORT_PROVIDERS", raising=False)
    assert resolve_ort_providers() == ["CPUExecutionProvider"]


def test_resolve_ort_env_override_appends_cpu(monkeypatch):
    monkeypatch.delenv("TRACE_ORT_PROVIDERS", raising=False)
    assert resolve_ort_providers("OpenVINOExecutionProvider") == [
        "OpenVINOExecutionProvider",
        "CPUExecutionProvider",
    ]


def test_use_fp16_only_on_cuda_by_default(monkeypatch):
    monkeypatch.delenv("TRACE_DTYPE", raising=False)
    assert use_fp16("cuda") is True
    assert use_fp16("mps") is False
    assert use_fp16("cpu") is False
    monkeypatch.setenv("TRACE_DTYPE", "fp32")
    assert use_fp16("cuda") is False
    monkeypatch.setenv("TRACE_DTYPE", "fp16")
    assert use_fp16("cpu") is True


def test_describe_accelerators_never_raises(monkeypatch):
    monkeypatch.setitem(sys.modules, "torch", None)
    monkeypatch.setitem(sys.modules, "onnxruntime", None)
    info = describe_accelerators()
    assert info["torch_device"] == "cpu"
    assert info["ort_providers"] == "CPUExecutionProvider"


def test_device_module_has_no_heavy_imports():
    import ast
    from pathlib import Path

    tree = ast.parse(Path(device_mod.__file__).read_text(encoding="utf-8"))
    top_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top_imports.add(node.module.split(".")[0])
    assert top_imports <= {"os", "typing"}, (
        f"device.py must stay dependency-free, found {top_imports}"
    )
