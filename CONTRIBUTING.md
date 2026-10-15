# Contributing to TRACE

Thanks for contributing. This guide gets you from fork to green CI.

## 1. Fork + upstream workflow

Upstream for pull/push is `https://github.com/auraflaa/TRACE.git`.

```bash
git clone https://github.com/<you>/TRACE.git
cd TRACE
git remote add upstream https://github.com/auraflaa/TRACE.git
git fetch upstream
git checkout -b feat/<short-name>
# ... work ...
git push origin feat/<short-name>
```

Open the PR against `auraflaa/TRACE:main`. Keep PRs under ~400 lines when possible.

## 2. Requirements

| Tool | Supported | Notes |
|---|---|---|
| Python | 3.11, 3.12, 3.13 | `requires-python = >=3.11`; CI tests all three |
| Node | 18.x, 20.x | Only needed for `npx trace-sec` / `bin/` checks |
| OS | Windows x64, Linux x64, macOS Intel + Apple Silicon | CI matrix covers all three |
| RAM | 4 GB lite / 8 GB full | Lite = `pip install -e .`; full AI = `requirements.txt` |

Heavy AI deps (`torch`, `transformers`, `onnxruntime`) are intentionally **not** in
`pyproject.toml`. Install them only when you need model inference:

```bash
pip install -r requirements.txt
```

## 3. Setup (all devices)

Windows (`cmd.exe`):

```cmd
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
set PYTHONPATH=src
python -m pytest tests/test_trace.py -q
```

Linux / macOS (`bash`):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
PYTHONPATH=src python -m pytest tests/test_trace.py -q
```

No `PYTHONPATH` needed after `pip install -e .` in a fresh shell if the
`trace` entry point is used, but tests should always run with
`PYTHONPATH=src` (also set in `pyproject.toml` for pytest ≥ 7).

## 4. Checks before pushing

```bash
python -m compileall -q src tests
ruff check src tests
ruff format --check src tests
PYTHONPATH=src python -m pytest tests/ -q
node --check bin/trace.js
npm pack --dry-run
```

Docs changes need one more check (installs `mkdocs` + `material` once):

```bash
pip install -e ".[docs]"
mkdocs build --strict
```

For model-free environments set `HF_HUB_OFFLINE=1` (CI does this).

## 5. Commit + PR rules

- Small, reversible commits; conventional style (`fix:`, `feat:`, `docs:`, `ci:`).
- Never commit secrets, `.trace/` output, `*.sarif`, model binaries
  (`*.pt`, `*.onnx`, `*.safetensors` go through Git LFS).
- Update `README`/`docs/` when behavior changes, and add a `CHANGELOG.md`
  entry under `[Unreleased]`.
- Fill the PR template: verification commands, device matrix, checklist.

## 6. Security contributions

Do not open public issues for vulnerabilities. See `SECURITY.md`.
Fuzzing and exploit PoCs must target `testbed_hardcore/` or `labs/`
— never public hosts (see `ScopeGuard` in `src/trace_engine/policy/scope.py`).

## 7. Releases

1. Bump `src/trace_engine/__init__.py:__version__` **and** `package.json`
   together — CI fails the release if either drifts from the tag.
2. Commit, tag `v<version>`, push the tag, then publish a GitHub release.
3. `release.yml` verifies the tag, then publishes to PyPI (one-time setup:
   add this repo as a trusted publisher at pypi.org) and NPM.
   The NPM step skips gracefully when `NPM_TOKEN` is not configured and
   fails only on real registry errors.
