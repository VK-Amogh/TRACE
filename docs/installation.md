# Installation

## Requirements

| Tool | Supported | Notes |
|---|---|---|
| Python | 3.11, 3.12, 3.13 | `requires-python = >=3.11` |
| Node | 18.x, 20.x | Only for the `npx trace-sec` shim |
| OS | Windows x64, Linux x64, macOS Intel + Apple Silicon | CI-tested |
| RAM | 4 GB lite / 8 GB full | Full = AI inference with torch |

## Lite install (recommended for contributors)

No torch, no model downloads — everything needed for tests and audits:

=== "Windows"

    ```cmd
    python -m venv .venv
    .venv\Scripts\activate
    python -m pip install --upgrade pip
    pip install -e ".[dev]"
    ```

=== "Linux / macOS"

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    pip install -e ".[dev]"
    ```

## Full AI install (inference on your machine)

```bash
pip install -r requirements.txt
```

This pulls `torch`, `transformers`, and `onnxruntime` (hundreds of MB).
On low-RAM or metered devices, stay on lite — detection still works, neural
scoring gracefully degrades. See [Lite or Full](lite-or-full.md).

## NPM shim

```bash
npm install -g trace-sec
trace
```

or zero-install: `npx trace-sec audit .`

## Verify the install

```bash
trace doctor
trace audit ./testbed_hardcore --format table
```

If `python -m trace_engine.cli` says `No module named 'trace_engine'`, set
`PYTHONPATH=src` (or use the repo launchers `trace.bat` / `trace.cmd` /
`trace.ps1`, which do it automatically). More in
[Troubleshooting](troubleshooting.md).
