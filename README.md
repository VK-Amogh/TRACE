# TRACE — Threat Reconnaissance & Attack-path Correlation Engine (v2.1)

[![Security Gate](https://github.com/VK-Amogh/TRACE/actions/workflows/trace-gate.yml/badge.svg)](https://github.com/VK-Amogh/TRACE/actions/workflows/trace-gate.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/NPX-Zero--Install-mint.svg)](https://nodejs.org/)
[![AI Models](https://img.shields.io/badge/AI_Models-SecureBERT_2.0_%2B_Laya_System_1-emerald.svg)](https://huggingface.co/ehsanaghaei/SecureBERT)

> **Threat Reconnaissance & Attack-path Correlation Engine** — A local-first, zero-telemetry neuro-symbolic security intelligence engine, autonomous agent harness, and deterministic verification layer for AI coding agents (Claude Code, Antigravity, Cursor, Codex, OpenHands).

---

## 🚀 Instant Zero-Install Quickstart (NPX)

Run TRACE immediately on any machine with Node.js installed without cloning or manual configuration:

```bash
# Launch interactive step-by-step security wizard (via NPM)
npx @vk.amogh/trace

# Or run directly from GitHub
npx github:VK-Amogh/TRACE

# Run comprehensive vulnerability audit across all source files and AI models
npx @vk.amogh/trace audit .

# Interactive Architecture & "How It Works" Guide
npx @vk.amogh/trace how-it-works
```

Or install globally via npm:
```bash
npm install -g @vk.amogh/trace
trace welcome
```

---

## 🤖 AI Coding Agent Integration (Claude Code, Antigravity, Cursor)

TRACE was purpose-built to act as the **ground-truth verification oracle** for autonomous AI coding agents.

### 1-Click Skill & MCP Installation
Run this single command inside any repository you want your coding agent to audit and repair:

```bash
npx @vk.amogh/trace install-skill
```

This immediately registers:
- **Claude Code Integration:** Configures `.mcp.json` and installs `.claude/skills/trace-security/`
- **Antigravity / Agentic IDEs:** Installs `.agents/plugins/trace-security/` with rules and skill runbooks
- **Cursor IDE Integration:** Generates `.cursor/mcp.json`

### Connect Directly to Claude Code CLI
```bash
claude mcp add trace -- npx -y @vk.amogh/trace mcp
```

### Registered Agent MCP Tools:
| Tool Name | Description |
|---|---|
| `trace_scan` | Full static AST + Attack-Path Model (APM) + live exploit correlation |
| `trace_findings` | Query correlated findings with AST code evidence and reproduction steps |
| `trace_explain` | Deep-dive root-cause analysis with zero-dummy-bypass remediation guidance |
| `trace_verify` | Live deterministic verification oracle proving whether an agent's patch fixed the flaw |
| `trace_harness_task` | Generate standardized benchmark tasks for the current unmitigated vulnerability |
| `trace_eval_patch` | Score patches produced by external agents with rollback protection |

---

## 🧠 Bundled Neural Intelligence Stack (SecureBERT 2.0 & Laya System 1)

TRACE does **not** rely solely on static heuristics. It incorporates a fine-tuned dual-engine neural stack bundled directly with the repository via **Git LFS**:

1. **SecureBERT 2.0 Semantic Vulnerability Classifier (`ehsanaghaei/SecureBERT` fine-tuned):**
   - 125M parameter transformer specialized in cybersecurity AST token semantics.
   - Accurately classifies vulnerability classes: **BOLA/IDOR, BFLA, SSRF, Injection (SQLi/Command), Broken Authentication, Mass Assignment, Path Traversal, CORS**.
   - Offline cached token representations for instant classification.

2. **Laya System 1 Decision Engine (`convaiinnovations/laya` fine-tuned):**
   - Dual-head priority router with ONNX Runtime sub-millisecond execution (<0.5ms per endpoint).
   - Dynamically triages high-risk routes into `P0 (Critical Exploit Path)` down to `P3 (Informational)`.

### Zero-Setup Model Verification
When cloned or installed, TRACE automatically loads the bundled fine-tuned checkpoints from `.trace/models/`:
```bash
trace intelligence
```
Output:
```text
TRACE Intelligence Stack Status
  • Laya System 1 Decision Engine: ONLINE (convaiinnovations/laya loaded on CPU)
  • SecureBERT 2.0 Semantic Classifier: ONLINE (.trace/models/securebert-finetuned)
  • Model Hierarchy: Deterministic -> SecureBERT -> Laya System 1 -> Local LLM
```

---

## 🛡️ Core Architecture & Operational Guarantees

TRACE operates on three strict architectural invariants:

```
  ┌─────────────────────────┐
  │ Multi-Language AST Code │ (Python, TypeScript, JavaScript, Go, Java, Kotlin, PHP)
  └────────────┬────────────┘
               ▼
  ┌─────────────────────────┐
  │ Attack-Path Model (APM) │ Directed graph: Endpoints ➔ Handlers ➔ Auth Gates ➔ Sinks
  └────────────┬────────────┘
               ▼
  ┌─────────────────────────┐
  │ Neural Intelligence     │ SecureBERT 2.0 + Laya System 1 Dual-Engine Scoring
  └────────────┬────────────┘
               ▼
  ┌─────────────────────────┐
  │ ScopeGuard Runtime DAST │ RFC-1918 / Localhost Sandboxed Active Probing
  └────────────┬────────────┘
               ▼
  ┌─────────────────────────┐
  │ Ground-Truth Findings   │ 100% Correlated Evidence (Zero False Positives)
  └────────────┬────────────┘
               ▼
  ┌─────────────────────────┐
  │ Agent Remediation Loop  │ Auto-patching + Verification Oracle + SWE-bench Export
  └─────────────────────────┘
```

1. **100% Local-First & Offline:**
   - Operates completely on your local workstation. Zero external cloud telemetry or proprietary API dependencies.
2. **ScopeGuard Boundary Enforcement:**
   - Dynamic probing is hard-isolated to localhost and authorized development containers. Cloud destinations and third-party APIs are rejected at the socket layer.
3. **Zero-False-Positive Guarantee:**
   - Flaws are only promoted to `CONFIRMED` when both static AST attack paths and live runtime oracles prove exploitability.

---

## 💻 CLI Command Reference

### Comprehensive Audits & Testing
```bash
# Interactive guided terminal audit wizard
trace

# Full repository audit across all languages, test packs, and AI models
trace audit [PATH]

# End-to-end scan with target URL and SARIF report export
trace scan [PATH] --target http://127.0.0.1:18080 --format sarif -o results.sarif

# Explain a specific finding with reproduction curl commands
trace explain TR-BOLA-001

# Replay exact HTTP reproduction steps
trace replay TR-BOLA-001
```

### Autonomous Remediation & Benchmarking
```bash
# Run self-healing remediation loop (synthesize fix, apply patch, verify oracle)
trace heal [PATH]

# Verify if a developer or coding agent's code change resolved a finding
trace verify TR-BOLA-001

# Benchmark coding agent performance against TRACE-Bench v1.0 scorecard
trace bench [PATH] --model "Claude-3.7-Sonnet"

# Export benchmark instances to SWE-bench JSONL format
trace plugin export -o swebench_tasks.jsonl
```

### System Inspection & Labs
```bash
# Environment diagnostic check (Tree-sitter, SQLite, PyTorch, Tool Adapters)
trace doctor

# Start reference vulnerable Vending API lab
trace lab start --port 18080
```

---

## 🛠️ Python Local Installation (Alternative)

If developing directly inside Python:

```bash
git clone https://github.com/VK-Amogh/TRACE.git
cd TRACE

# Ensure Git LFS pulls the model checkpoints
git lfs pull

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate

# Install editable package
pip install -e .

# Run test suite (63 unit tests)
pytest
```

---

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE) for details.
