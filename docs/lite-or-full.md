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
