# Lite or Full

| | **Lite** (default) | **Full** |
|---|---|---|
| Install | `pip install -e .` | `pip install -r requirements.txt` |
| Size | ~2 MB, no torch | ~1 GB (torch, transformers, onnxruntime) |
| Runs on | any CPU, 4 GB RAM | 8 GB RAM recommended |
| Detection | AST dataflow + live probes | + SecureBERT 2.0 neural scoring and Laya router |
| Confidence | heuristic fusion | triple-signal Bayesian fusion (~99.8% on triple match) |
| Choose it | contributors, CI, quick audits | maximum confidence on your own machine |

`trace doctor` reports which mode is active. Missing models never block a scan:
the engine warns once and continues with deterministic analysis.

## Accelerators (full install)

Device selection is automatic, with CPU always as fallback:

| Hardware | torch path | ONNX path | Install note |
|---|---|---|---|
| NVIDIA GPU (CUDA) | ✅ auto + fp16 | ✅ via `onnxruntime-gpu` | stock `pip install torch` bundles CUDA |
| Apple Silicon GPU | ✅ via MPS | ✅ via CoreML EP (ships in stock onnxruntime) | nothing extra |
| AMD GPU, Linux (ROCm) | ✅ auto (CUDA API) | CPU fallback | `pip install torch --index-url https://download.pytorch.org/whl/rocm6.x` |
| Intel CPU/iGPU | CPU | ✅ via `onnxruntime-openvino` | `pip install onnxruntime-openvino` |

Overrides: `TRACE_DEVICE=cuda|mps|cpu`, `TRACE_DTYPE=fp16|fp32`,
`TRACE_ORT_PROVIDERS=CUDAExecutionProvider,CPUExecutionProvider`.
`trace doctor` prints the active `torch_device`, ORT providers, and fp16 state
in its Accelerators row. Native MLX is intentionally unsupported — CoreML
covers Apple acceleration with no model conversion.
