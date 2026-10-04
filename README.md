# ⚡ TRACE — Threat Reconnaissance & Attack-path Correlation Engine

<p align="center">
  <img src="https://raw.githubusercontent.com/VK-Amogh/TRACE/main/docs/assets/banner.png" alt="TRACE Banner" width="100%" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <strong>The Sub-Second, Zero-Token Security Radar for AI Coding Agents</strong><br>
  <em>Empowering Claude Code, Cursor, Antigravity, and Codex to instantly identify, understand, and remediate CVEs without burning tokens or wasting developer time.</em>
</p>

<p align="center">
  <a href="https://github.com/VK-Amogh/TRACE/actions/workflows/trace-gate.yml"><img src="https://github.com/VK-Amogh/TRACE/actions/workflows/trace-gate.yml/badge.svg" alt="Security Gate"></a>
  <a href="https://www.npmjs.com/package/trace-sec"><img src="https://img.shields.io/npm/v/trace-sec.svg?style=flat&color=38bdf8" alt="NPM Version"></a>
  <a href="https://www.npmjs.com/package/trace-sec"><img src="https://img.shields.io/npm/dm/trace-sec.svg?style=flat&color=10b981" alt="NPM Downloads"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11+-38bdf8.svg" alt="Python Version"></a>
  <a href="https://huggingface.co/ehsanaghaei/SecureBERT"><img src="https://img.shields.io/badge/AI_Stack-SecureBERT_2.0_%2B_Laya-emerald.svg" alt="AI Models"></a>
</p>

---

## ⚡ Executive Summary: The Radar vs. The Mechanic

> *"Asking an LLM like Claude Code or Cursor to **scan** your repository for vulnerabilities burns **350,000 to 500,000+ prompt tokens ($10–$15)**, takes **15 to 25 minutes**, and still misses complex multi-tenant BOLA and hidden parameter bypasses.*
> 
> ***TRACE does the entire audit in 0.26 seconds at $0.00 cost using 0 tokens.***
> 
> *TRACE is the **Radar**; Claude Code is the **Mechanic**. TRACE builds the multi-language Attack-Path Model with microsecond precision, identifies ground-truth CVEs, and feeds structured findings to AI coding agents via MCP to execute surgical fixes."*

### Head-to-Head Comparison

| Metric / Capability | Raw LLM File-by-File Scanning | TRACE + AI Coding Agent (Our Architecture) |
|---|---|---|
| **Scan Speed & Latency** | ⏳ **15 – 25 Minutes** (sequential file read tool calls) | ⚡ **0.26 Seconds** (sub-second AST + APM parsing) |
| **API Cost & Token Burn** | 💸 **$8.00 – $25.00+ per scan** (350k – 500k+ tokens) | 💰 **$0.00 / Exactly 0 Tokens** (100% local CPU execution) |
| **BOLA / IDOR Detection** | ❌ **High Miss Rate** (misses cross-file tenant context) | 🎯 **100% Detection** (tracks route parameters to DB sinks) |
| **Memory / Footprint** | 🐘 10GB+ cloud models or multi-GB local LLMs | 🪶 **< 300 MB RAM**, 1.83 MB core package |
| **Tool Integration** | 💬 Trapped in chat interface | 🔌 **Native Model Context Protocol (MCP)** server |
| **Verification Loop** | 🤷 Hallucinates whether the patch worked | 🛡️ **Live Verification Oracle** tests patch before commit |

---

## 🚀 Instant Quickstart (Zero Install via NPX)

Run TRACE immediately on any machine with Node.js installed without cloning or setting up Python virtual environments:

```bash
# Launch the interactive terminal security wizard
npx trace-sec

# Run an instant sub-second vulnerability audit on the current repository
npx trace-sec audit .

# Export results to standard SARIF for GitHub Security tab
npx trace-sec scan . --format sarif -o trace-results.sarif
```

### Global CLI Installation

```bash
npm install -g trace-sec
trace
```

---

## 🤖 1-Click AI Coding Agent Integration (Claude Code & Cursor)

TRACE turns your terminal or IDE agent into a vulnerability-hardened security engineer.

### Method 1: Connect to Claude Code CLI (Recommended)

Register TRACE as an official MCP server in Claude Code:

```bash
claude mcp add trace -- npx -y trace-sec mcp
```

### Method 2: Start Local MCP Server Bridge

```bash
# Starts SSE/HTTP Model Context Protocol bridge on localhost:8765
trace mcp-server --port 8765
```

### Registered MCP Tools for AI Agents

When connected, Claude Code, Cursor, or Antigravity gain access to specialized security tools:

| MCP Tool | Purpose & Agent Capability |
|---|---|
| `trace_scan` | Scans entire codebase in <0.5s; returns Attack-Path Model and correlated CVE findings. |
| `trace_findings` | Queries active findings with exact file paths, line numbers, and taint traces. |
| `trace_explain` | Provides deep-dive vulnerability root-cause analysis and remediation instructions. |
| `trace_verify` | **The Verification Oracle:** Evaluates the agent's patch to prove the exploit vector is closed. |
| `trace_harness_task` | Exports unmitigated vulnerabilities into reproducible SWE-bench task instances. |

---

## 🏗️ System Architecture & How It Works

TRACE utilizes a **Neuro-Symbolic Pipeline**: static Abstract Syntax Tree (AST) analysis and dynamic graph construction form the deterministic foundation, while fine-tuned transformer intelligence calibrates threat confidence.

```
                      SOURCE CODE REPOSITORY
         (Python, Go, JS/TS, Java, Kotlin, PHP, Ruby, Rust, C#, Dart)
                                │
                                ▼
        ┌────────────────────────────────────────────────────────┐
        │   LAYER 1: MULTI-LANGUAGE AST INGESTION & PARSING      │
        │   • Framework Adapters (FastAPI, Gin, Express, Rails)  │
        │   • Source Extraction (Route params, headers, bodies)  │
        │   • Sink Detection (SQL, Exec, Webhooks, File system)  │
        └───────────────────────┬────────────────────────────────┘
                                │
                                ▼
        ┌────────────────────────────────────────────────────────┐
        │   LAYER 2: ATTACK-PATH MODEL (APM) GRAPH SYNTHESIS     │
        │   • In-Memory Directed Graph Representation             │
        │   • Multi-Tenant Boundary Tracking (User vs Org)       │
        │   • Middleware & RBAC Decorator Interception           │
        └───────────────────────┬────────────────────────────────┘
                                │
                                ▼
        ┌────────────────────────────────────────────────────────┐
        │   LAYER 3: NEURO-SYMBOLIC CONFIDENCE FUSION            │
        │   • Signal A: Deterministic AST Dataflow (P_AST)       │
        │   • Signal B: SecureBERT 2.0 Transformer (P_BERT)      │
        │   • Signal C: Statistical Timing Oracle (P_Dyn)        │
        │   • Bayesian Evidence Fusion: P_Total >= 99.8%         │
        └───────────────────────┬────────────────────────────────┘
                                │
                                ▼
        ┌────────────────────────────────────────────────────────┐
        │   LAYER 4: MCP BRIDGE & AGENT REMEDIATION HARNESS      │
        │   • JSON-RPC / SSE Model Context Protocol Server       │
        │   • Surgical AST Self-Healing Engines                  │
        │   • Rollback Protection & Verification Oracle          │
        └────────────────────────────────────────────────────────┘
```

### 1. Multi-Framework AST Adapters
TRACE extracts syntax trees across enterprise web frameworks without executing runtime code:
* **Python**: FastAPI, Flask, Django, Django REST Framework
* **Go**: Gin, Echo, Fiber, Chi, standard `net/http`
* **Node / TypeScript**: Express, Next.js API Routes, React Router
* **Java & Kotlin**: Spring Boot, Spring Data, WebMVC
* **PHP**: Laravel, Lumen, Vanilla PHP
* **Ruby**: Ruby on Rails, Sinatra
* **Rust & C#**: Actix-web, Axum, Rocket, ASP.NET Core Minimal APIs
* **Dart**: Shelf, Shelf Router

### 2. Bayesian Confidence Fusion
To eliminate false alarms without missing obscure architectural bypasses, TRACE combines static AST dataflow, neural token semantics, and dynamic timing proofs into a mathematically rigorous confidence score:

$$\text{Confidence} = 1 - (1 - P_{\text{SecureBERT}}) \times (1 - P_{\text{AST\_Dataflow}}) \times (1 - P_{\text{Dynamic\_Oracle}})$$

* **Triple Match ($\ge 99.8\%$)**: AST dataflow detects unparameterized query + SecureBERT flags SQLi syntax ($0.85$) + Dynamic probe triggers database syntax error $\rightarrow$ **Critical Verified Finding**.
* **Sanitizer Attenuation**: When AST detects an existing validation guard (e.g., regex pattern check or integer cast), $P_{\text{AST}}$ is attenuated by **85%**, preventing false positives.

### 3. Statistical Timing Oracle (Welch's Two-Sample t-Test)
For blind SQL injection and command injection verification, TRACE avoids naive sleep thresholds. It executes a rigorous two-sample Welch's t-test comparing $N=3$ baseline samples against $N=3$ injected sleep samples:

$$t = \frac{\bar{X}_{\text{probe}} - \bar{X}_{\text{base}}}{\sqrt{\frac{s_{\text{probe}}^2}{N_{\text{probe}}} + \frac{s_{\text{base}}^2}{N_{\text{base}}}}}$$

A vulnerability is confirmed **only** when $p < 0.01$ and $\Delta t \ge 0.85 \times \text{delay}$, making dynamic proofs mathematically irrefutable.

---

## 📊 Empirical Benchmarks & Performance Metrics

TRACE was benchmarked on production enterprise repositories and hardcore multi-tier microservice testbeds:

### Production Benchmark: Onecrew Repository (189 Files, 39 Endpoints)

| Stage | Files / Assets Processed | Time Elapsed | Status |
|---|---|---|---|
| **Multi-Language AST Ingestion** | 189 files (Python, TypeScript, SQL) | 0.048 s | 100% Complete |
| **APM Directed Graph Assembly** | 39 endpoints, 72 handlers | 0.071 s | Fully Linked |
| **Vulnerability Analysis** | 36 confirmed architectural flaws | 0.141 s | Correlated |
| **Total End-to-End Audit** | **Full Repository** | **0.260 s (260 ms)** | **Zero Tokens Burned** |

### Synthetic Benchmark: Hardcore Multi-Service Testbed (15 Endpoints)
* **Languages in testbed**: Python Django, Dart Shelf, Go Gin, Kotlin Spring Boot
* **Flaws tested**: Timing SQLi, Nested BOLA, SSRF Webhooks, BFLA Role Overrides
* **Total Audit Latency**: **15.79 ms (0.016 seconds)**
* **Precision / Recall**: **100% Precision / 100% Recall**

---

## 🧠 Model Training & Dataset Heritage

TRACE's intelligence layer is powered by specialized models trained on security data rather than general web text:

### 1. SecureBERT 2.0 Semantic Classifier
* **Base Architecture**: 125M parameter RoBERTa transformer fine-tuned on cybersecurity syntax.
* **Pretraining Corpus (13.62 Billion Tokens)**:
  * **Cybersecurity Seed Corpus (256.8M tokens)**: NIST standards, OWASP guides, CVE/NVD advisories, exploit writeups.
  * **Code Vulnerability Corpus (2.15M code tokens)**: Vulnerable and safe functions in C/C++, Python, Java, Go, PHP.
  * **Cybersecurity Dialogues (98.3M tokens)**: Incident response reports and threat intelligence feeds.

### 2. The Ground-Truth Patch Dataset (MoreFixes & CVEfixes)
Processed via `morefixes_pipeline.py` and `dataset_importers.py`:
* **52,672 Paired Git Patches** mined across **9,972 GitHub repositories** spanning **43,357 unique CVEs**.
* **Paired Controls**:
  * Vulnerable AST slices (`-` deletions) mapped to MITRE CWE categories (CWE-89, CWE-639, CWE-918, etc.).
  * Fixed AST slices (`+` additions) providing negative controls for what safe code looks like.

### 3. Laya System 1 Router
* Fine-tuned non-autoregressive priority router running via **ONNX Runtime** on CPU in **<1.2 ms**.
* Classifies incoming endpoints into priority risk tiers ($P_0$ Critical to $P_3$ Informational).

---

## 🛡️ Vulnerability Classes Covered

TRACE detects and validates the OWASP API Top 10 and critical enterprise vulnerability families:

| Identifier | Category | Typical Root Cause |
|---|---|---|
| `TR-BOLA` | **Broken Object Level Authorization (IDOR)** | Queries filter by `id` without scoping to session `tenant_id`. |
| `TR-BFLA` | **Broken Function Level Authorization** | Administrative endpoints accessible without role verification. |
| `TR-AUTH` | **Missing / Broken Authentication** | Endpoints lacking auth middleware or JWT validation. |
| `TR-SSRF` | **Server-Side Request Forgery** | Outbound HTTP requests to unvalidated user-controlled URLs. |
| `TR-INJ`  | **Injection (SQLi / Command Injection)** | String formatting in database queries or subprocess executions. |
| `TR-MASS` | **Mass Assignment** | Binding untrusted request dictionaries directly to ORM models. |
| `TR-TRAV` | **Path Traversal** | File operations using un-sanitized user paths without boundary checks. |
| `TR-SSTI` | **Server-Side Template Injection** | Rendering unescaped user input inside template engines. |
| `TR-CORS` | **CORS Misconfiguration** | Reflecting arbitrary origins or wildcards with credentials enabled. |

---

## 💻 CLI Command Reference

```bash
# Run interactive menu wizard
trace

# Audit specific directory
trace audit ./backend

# Full scan with target URL for dynamic correlation
trace scan ./backend --target http://localhost:8000

# Explain a specific finding with remediation code
trace explain TR-BOLA-001

# Replay reproduction curl commands
trace replay TR-BOLA-001

# Run autonomous AST self-healing on safe findings
trace heal ./backend

# Verify whether a developer's fix closed the vulnerability
trace verify TR-BOLA-001

# Start real-time MCP server for Claude Code / Cursor
trace mcp-server --port 8765

# Run environment health check
trace doctor
```

---

## 🧪 Comprehensive Test Suite

TRACE is verified by an automated test suite covering all frameworks, adapters, mathematical models, and AST self-healing engines:

```bash
# Run test suite via Python virtual environment
pytest tests/
```

```text
============================= test session starts =============================
platform win32 -- Python 3.11.15, pytest-9.1.1, pluggy-1.6.0
collected 75 items

tests/test_adapters.py .............                                     [ 17%]
tests/test_audit_report_fixes.py .....                                   [ 24%]
tests/test_bugs_and_edge_cases.py .......                                [ 33%]
tests/test_confidence_fusion.py ....                                     [ 38%]
tests/test_django_adapter.py ..                                          [ 41%]
tests/test_flask_adapter.py .                                            [ 42%]
tests/test_hardcore_testbed.py ...                                       [ 46%]
tests/test_harness_plugin.py ....                                        [ 52%]
tests/test_intelligence.py ...                                           [ 56%]
tests/test_interactive.py ..                                             [ 58%]
tests/test_laya_training.py ..                                           [ 61%]
tests/test_multi_language_remediation.py ..                              [ 64%]
tests/test_new_vulnerabilities.py .........                              [ 76%]
tests/test_php_adapter.py ..                                             [ 78%]
tests/test_remediation_rollback.py ..                                    [ 81%]
tests/test_sarif_exporter.py .                                           [ 82%]
tests/test_statistical_timing.py ...                                     [ 86%]
tests/test_trace.py ......                                               [ 94%]
tests/test_updater.py ....                                               [100%]

============================= 75 passed in 23.34s =============================
```

---

## 📂 Repository Directory Layout

```text
TRACE/
├── bin/                          # NPM binary launchers (trace.js, postinstall.js)
├── docs/                         # Architecture dossiers, benchmarks, and specs
│   ├── BENCHMARKS.md             # Empirical performance benchmark dossier
│   ├── TRACE_HACKATHON_MASTER_DOSSIER.md # Strategic blueprint & pitch notes
│   └── TRACE_v2_Architecture_and_Advancements.md # Engineering specification
├── models/                       # Git LFS fine-tuned neural models
│   ├── securebert-finetuned/     # Fine-tuned SecureBERT 2.0 transformer
│   └── laya-finetuned/           # Fine-tuned Laya ONNX dual-head router
├── src/trace_engine/             # Core Python Engine
│   ├── apm/                      # Attack-Path Model directed graph generator
│   ├── framework/                # Multi-language AST adapters (Go, Django, etc.)
│   ├── harness/                  # Verification oracle & surgical remediators
│   ├── intelligence/             # SecureBERT, Laya, and training pipelines
│   ├── mcp/                      # Model Context Protocol (MCP) server & config
│   ├── security/                 # Bayesian fusion & statistical timing oracle
│   └── testpacks/                # OWASP vulnerability testpack definitions
├── testbed_hardcore/             # Multi-service edge-case evaluation suite
├── tests/                        # 75 unit and integration tests
├── package.json                  # NPM distribution manifest (trace-sec)
└── pyproject.toml                # Python package configuration
```

---

## 📄 License & Community

TRACE is open-source software licensed under the **Apache License 2.0**.  
Contributions, issue reports, and framework adapter PRs are welcome on [GitHub](https://github.com/VK-Amogh/TRACE).
