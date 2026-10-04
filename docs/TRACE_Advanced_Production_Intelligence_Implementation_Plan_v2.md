# TRACE — Advanced Production & Intelligence Implementation Plan
## Version 2.0

**TRACE:** Threat Reconnaissance & Attack-path Correlation Engine

### Product boundary

TRACE is the **security verification layer for AI-assisted software development**.

TRACE:

- discovers attack surface;
- reconstructs attack paths;
- classifies security-relevant paths;
- selects safe, high-information tests;
- runs local/authorized security tests;
- correlates source and runtime evidence;
- generates structured findings;
- exposes findings through MCP;
- verifies whether a coding agent actually fixed the finding.

TRACE does **not**:

- patch source code;
- modify application source;
- make Git commits;
- autonomously decide arbitrary shell commands;
- upload source code;
- require cloud APIs;
- act as the remediation agent.

Remediation belongs to Claude Code, Codex, or another MCP-compatible coding agent.

---

# 1. Final Product Philosophy

The final product loop is:

```text
CONNECT REPOSITORY
       ↓
TRACE INDEXES
       ↓
TRACE BUILDS ATTACK-PATH MODEL
       ↓
TRACE IDENTIFIES SECURITY SIGNALS
       ↓
TRACE SELECTS SAFE TESTS
       ↓
TRACE RUNS LOCAL TESTS
       ↓
TRACE CORRELATES EVIDENCE
       ↓
TRACE GENERATES REPORT
       ↓
CLAUDE CODE / CODEX RECEIVES FINDINGS
       ↓
CODING AGENT FIXES SOURCE
       ↓
TRACE VERIFY
       ↓
PASS / STILL PRESENT / INCONCLUSIVE
```

The user should not need to understand the internal architecture.

The normal workflow should feel like:

```bash
npx -y @trace-security/trace
```

Then:

```text
Repository detected
Framework detected
Local target detected
Security environment checked

[ Enter ] Start full audit
```

Everything else should happen automatically.

---

# 2. What Makes TRACE Different

TRACE should **not** compete with:

- ZAP
- Nuclei
- Semgrep
- Schemathesis
- Gitleaks
- OSV-Scanner
- Nmap
- SQLMap
- other specialized security tools

Instead:

```text
TRACE = orchestration + attack-path understanding + evidence correlation
```

External tools become engines that TRACE can schedule.

The key abstraction is:

# Attack-Path Model

Example:

```text
GET /api/orders/{id}
        ↓
JWT Middleware
        ↓
OrderController
        ↓
OrderService
        ↓
OrderRepository
        ↓
orders.id
```

TRACE attaches security properties:

```text
authenticated = true
object_identifier = true
database_access = true
ownership_check = not_detected
state_change = false
sensitive_data = true
```

TRACE then asks:

> What is the most informative safe experiment that can distinguish a safe implementation from a vulnerable one?

That question is the center of the product.

---

# 3. Core Architectural Layers

```text
                         TRACE
                           │
                 ┌─────────┴─────────┐
                 │                   │
                CLI                  MCP
                 │                   │
                 └─────────┬─────────┘
                           │
                     TRACE CORE
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ▼                   ▼                   ▼
 Source Analysis      Attack-Path Model     Runtime
       │                   │                   │
 Tree-sitter           NetworkX/SQLite       HTTPX
 ast-grep              Security signals      Test Packs
 framework adapters    source locations      Tool adapters
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
                   Intelligence Layer
                           │
            ┌──────────────┼───────────────┐
            ▼              ▼               ▼
        SecureBERT       Laya         Local Code LLM
        classifier      decisions       deep context
            │              │               │
            └──────────────┼───────────────┘
                           ▼
                   Test Orchestrator
                           │
                           ▼
                   Evidence Correlator
                           │
                 ┌─────────┴──────────┐
                 ▼                    ▼
             Findings             Attack Chains
                 │                    │
                 └─────────┬──────────┘
                           ▼
                          MCP
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
           Claude Code             Codex
                │                     │
                └──────────┬──────────┘
                           ▼
                         Fix
                           │
                           ▼
                      TRACE Verify
```

---

# 4. Intelligence Stack

Do NOT train one giant cybersecurity LLM.

Use specialized components.

## 4.1 SecureBERT 2.0

Repository:

https://github.com/cisco-ai-defense/securebert2

SecureBERT 2.0 is Cisco AI's cybersecurity-focused encoder model built on ModernBERT. Its repository provides code-vulnerability detection, semantic search, NER and threat-analysis components, along with released checkpoints and training/evaluation code.

TRACE uses it for:

```text
security relevance
vulnerability family classification
similarity / retrieval
source-security-slice classification
```

It is a **classifier/encoder**, not the final vulnerability authority.

---

## 4.2 Local code LLM

Recommended architecture:

```text
Ollama
   OR
llama.cpp
```

Use a local code-capable model such as a suitable Qwen-Coder or Llama-family model, selected according to hardware.

The model is used for:

```text
complex attack-path interpretation
test recipe selection when deterministic signals are ambiguous
runtime observation interpretation
finding explanation
```

It must never modify source.

---

## 4.3 Laya

Repository:

https://github.com/NandhaKishorM/laya

Use Laya as the fast decision layer.

Current Laya documentation describes it as a non-autoregressive System 1 decision engine supporting typed `choice`, `score`, and yes/no (`noul`) decisions, local execution, confidence gating, hooks, and an MCP/HTTP interface.

TRACE should use Laya for:

```text
should_test
test_priority
which_test
continue_testing
stop_testing
evidence_strength
attack_chain_relevance
```

Do not use Laya for long natural-language explanations.

---

# 5. Install Laya

Pin a tested version in the lockfile. The current upstream `pyproject.toml` reports version `0.3.21`; do not rely on an unpinned latest release for production builds.

```bash
uv add "laya==0.3.21"
```

Verify:

```bash
uv run python -I -c "import laya; print(laya.__version__)"
```

For optional HTTP serving:

```bash
uv add "laya[serve]==0.3.21"
```

For optional MCP server support:

```bash
uv add "laya[mcp]==0.3.21"
```

For typed schema helpers:

```bash
uv add "laya[structured]==0.3.21"
```

The initial TRACE integration should prefer the **in-process Python API** so there are fewer processes to fail.

Use the Laya HTTP or MCP server only when there is a deployment reason.

---

# 6. Laya Integration Contract

Create:

```text
src/trace/intelligence/laya/
├── __init__.py
├── router.py
├── schemas.py
├── prompts.py
├── thresholds.py
└── telemetry.py
```

Example decision:

```json
{
  "run": true,
  "score": 0.91,
  "reason_code": "strong_static_signal"
}
```

No prose is required.

---

# 7. Laya Decision Types

Implement:

## EndpointPriority

```text
0.0 → 1.0
```

## TestSelection

```text
BOLA
BFLA
AUTH
SSRF
INJECTION
MASS_ASSIGNMENT
...
```

## EvidenceStrength

```text
weak
moderate
strong
```

## ContinueTesting

```text
yes/no
```

## StopTesting

```text
yes/no
```

Laya should be allowed to **abstain** below a confidence threshold.

Recommended starting threshold:

```toml
[laya]
min_confidence = 0.82
```

Tune experimentally.

---

# 8. SecureBERT Integration

Create:

```text
src/trace/intelligence/securebert/
├── __init__.py
├── model.py
├── tokenizer.py
├── classifier.py
└── cache.py
```

Input:

```text
normalized endpoint
+
attack-path slice
+
security signals
+
relevant source snippets
```

Output:

```json
{
  "BOLA": 0.82,
  "BFLA": 0.13,
  "SSRF": 0.07,
  "INJECTION": 0.18
}
```

These values are prioritization signals, not proof.

---

# 9. Model Hierarchy

Final TRACE model hierarchy:

```text
Deterministic rules
      ↓
SecureBERT
      ↓
Laya
      ↓
local code LLM
      ↓
test selection
```

The local LLM should only be called when:

```text
high-value ambiguity
+
insufficient deterministic evidence
```

This keeps runtime cost down.

---

# 10. Do Not Train a Model From Scratch

Do not build:

```text
10B+ model
↓
pretraining
```

Instead:

```text
existing security model
+
TRACE-specific dataset
+
parameter-efficient fine-tuning
```

For the first release:

```text
SecureBERT existing checkpoint
Laya existing checkpoint
local code model unchanged
```

Then fine-tune after the benchmark pipeline works.

---

# 11. The Correct Dataset Strategy

No single public dataset matches TRACE's entire task.

TRACE requires:

```text
source code
+
endpoint
+
attack path
+
authorization relationship
+
runtime behavior
+
security test trajectory
```

Therefore use four data layers:

```text
Layer A
vulnerability-code datasets

Layer B
runnable security benchmarks

Layer C
JavaScript/API-specific datasets

Layer D
TRACE-generated runtime trajectories
```

Layer D should eventually become the most important dataset.

---

# 12. Best Public Dataset for TRACE's Actual Use Case

## Primary runtime benchmark: OWASP Benchmark Python

Repository:

https://github.com/OWASP-Benchmark/BenchmarkPython

The project describes itself as a runnable Python web application designed to benchmark SAST, DAST and IAST tools, with expected-result files and known test cases.

Use it as:

```text
runtime benchmark
static benchmark
false-positive benchmark
tool integration validation
```

This is more relevant to TRACE than a generic source-code classification dataset because TRACE is intended to connect source code with runtime security behavior.

---

# 13. Node.js / JavaScript Benchmark

## SecBench.js

Repository:

https://github.com/cristianstaicu/SecBench.js

Use it for:

```text
Node/JavaScript vulnerability classification
sink detection
runtime benchmark
hard-negative generation
```

The public project contains server-side JavaScript vulnerability cases involving areas such as:

```text
command injection
code injection
path traversal
prototype pollution
ReDoS
```

Verify each sample and preserve source provenance before using it as ground truth.

---

# 14. JavaScript Vulnerability Dataset

Repository:

https://github.com/jsvul/jsvul

The project references the U-Szeged JavaScript Vulnerability Dataset and related sources such as CrossVul, CVEFixes and SecBench.js.

Use it for:

```text
JavaScript vulnerability pretraining
vulnerability-family classification
hard negative construction
```

---

# 15. Kaggle Dataset

## Source Code Vulnerability Detection

https://www.kaggle.com/c/source-code-vulnerability/data

It contains `text_snippet` data specifically for vulnerable source-code detection.

However:

## Important

The current Kaggle competition rules explicitly state:

> Do not share or use the competition data outside the competition without direct approval from the dataset owner.

Therefore:

```text
Kaggle dataset
= research / benchmark input only
```

Do NOT bundle Kaggle-derived examples into a production TRACE model artifact unless you have permission.

This dataset can still be used to reproduce a research experiment and compare a classifier baseline.

---

# 16. CrossVul

Repository:

https://github.com/crossvul/crossvul

Use CrossVul for:

```text
vulnerable/fixed code pairs
contrastive learning
before/after representation
security regression learning
```

It is more useful to TRACE than a generic Kaggle dataset because TRACE ultimately needs to understand the difference between a vulnerable and remediated path.

---

# 17. PrimeVul

Repository:

https://github.com/DLVulDet/PrimeVul

Use it only as auxiliary research data.

Reason:

```text
PrimeVul
→ primarily C/C++ function-level vulnerability detection

TRACE
→ Python / JavaScript API attack paths
```

It should not dominate the TRACE model.

---

# 18. LLMVul

Repository:

https://github.com/Wahed08/LLMVul-Dataset

Use only as an auxiliary source for:

```text
LLM-generated code vulnerability classification
```

Again, it is not an API attack-path dataset.

---

# 19. TRACEBench — The Real Dataset

Build:

# TRACEBench

This should eventually become the main research/data asset.

A record looks like:

```json
{
  "repository": "trace-vending",
  "commit": "abc123",
  "endpoint": "GET /api/orders/{id}",
  "attack_path": [
    "endpoint",
    "auth",
    "controller",
    "service",
    "repository",
    "database"
  ],
  "signals": [
    "OBJECT_ID_TO_DB",
    "OWNERSHIP_CHECK_MISSING"
  ],
  "candidate_tests": [
    "anonymous",
    "cross_identity",
    "invalid_id"
  ],
  "executed_tests": [
    {
      "test": "cross_identity",
      "request_hash": "...",
      "result": "unauthorized_object_returned"
    }
  ],
  "ground_truth": "confirmed"
}
```

This is the dataset that matches TRACE's actual production problem.

---

# 20. Security Trajectory Dataset

Each TRACEBench trajectory:

```text
INITIAL STATE
      ↓
TEST 1
      ↓
OBSERVATION 1
      ↓
DECISION
      ↓
TEST 2
      ↓
OBSERVATION 2
      ↓
...
      ↓
FINAL STATUS
```

This trains the future TRACE policy.

---

# 21. Generate TRACEBench Automatically

Create:

```text
tracebench/
├── generator/
├── mutation/
├── runners/
├── oracles/
├── exporters/
└── validators/
```

Generate intentionally vulnerable synthetic projects.

Then:

```text
secure app
   ↓
controlled mutation
   ↓
vulnerable app
   ↓
Docker build
   ↓
runtime test
   ↓
ground truth
```

---

# 22. Mutation Engine

Implement mutations for:

```text
remove_auth_check
remove_role_check
remove_ownership_check
remove_url_allowlist
unsafe_sql_construction
unsafe_model_assignment
remove_validation
unsafe_redirect
unsafe_file_path
unsafe_state_transition
```

Every mutation must be:

```text
deterministic
reproducible
reversible
```

Only run mutations against TRACE-controlled training fixtures.

---

# 23. Secure/Vulnerable Pairs

Every generated example should preserve:

```text
secure version
vulnerable version
diff
attack path
expected result
runtime evidence
```

This enables:

```text
classifier training
contrastive training
regression testing
patch verification research
```

---

# 24. Hard Negatives

This is mandatory.

Example:

```text
object_id → database
```

could appear vulnerable.

But:

```text
object_id → database
+
explicit owner_id == current_user.id
```

is safe.

Generate both.

Other hard negatives:

```text
URL → HTTP client
but URL is allowlisted

admin route
but role guard exists

user input → SQL
but parameterized query is used

sensitive field
but server overwrites client value
```

This should be a major source of TRACE's false-positive resistance.

---

# 25. Dataset Split

Never randomly split individual functions from the same project.

Use:

```text
repository-level split
```

For TRACEBench also use:

```text
fixture-family split
```

Example:

```text
Training:
repositories A-M

Validation:
repositories N-R

Test:
repositories S-Z
```

For mutation-generated data:

```text
vulnerability family A/B/C
```

can also be held out by project.

---

# 26. SecureBERT Training Plan

Use the existing model checkpoint as the base.

Task:

```text
security-slice classification
```

Classes:

```text
NONE
AUTH
BOLA
BFLA
SSRF
INJECTION
MASS_ASSIGNMENT
PATH_TRAVERSAL
XSS
SECRETS
OTHER
```

---

# 27. Initial Training Mixture

Start experimentally with:

```text
50% TRACEBench
20% OWASP Benchmark Python
10% SecBench.js / JavaScript dataset
10% CrossVul
10% Kaggle research data
```

These are initial experiment weights, not established optimal ratios.

Because of Kaggle's competition rules, Kaggle data must remain segregated from a distributable production training pipeline unless permission is obtained.

Production model training should therefore have a second manifest:

```text
production-eligible-only.yaml
```

---

# 28. Training Environment

Create:

```text
training/
├── environments/
│   ├── securebert.yaml
│   └── trace-policy.yaml
├── datasets/
├── preprocessing/
├── train/
├── eval/
└── reports/
```

Install:

```bash
uv add \
  torch \
  transformers \
  datasets \
  accelerate \
  peft \
  evaluate \
  scikit-learn
```

Use GPU when available.

CPU fallback is acceptable for preprocessing/evaluation, but not expected to be efficient for fine-tuning larger checkpoints.

---

# 29. SecureBERT Dataset Normalization

Normalize everything to:

```json
{
  "id": "trace-000001",
  "source": "...",
  "language": "python",
  "repository": "...",
  "endpoint": "...",
  "context": "...",
  "label": "BOLA",
  "runtime_confirmable": true,
  "source_dataset": "TRACEBench",
  "source_license": "..."
}
```

Always keep:

```text
original ID
source URL
license
version
```

---

# 30. Fine-Tuning Strategy

Do not full-fine-tune first.

Stage 1:

```text
existing vulnerability checkpoint
+
classifier head
```

Stage 2:

```text
parameter-efficient fine-tuning
```

Stage 3:

```text
TRACEBench specialization
```

Possible technique:

```text
LoRA / PEFT
```

Only proceed if it improves held-out performance.

---

# 31. Evaluation

Measure:

```text
precision
recall
F1
MCC
PR-AUC
false-positive rate
false-negative rate
calibration
```

For actual TRACE utility:

```text
test-selection accuracy
confirmed-finding recall
requests per confirmed finding
time per confirmed finding
```

---

# 32. Main Model Experiment

Compare:

```text
Rules only
vs
Rules + SecureBERT
vs
Rules + SecureBERT + Laya
vs
Rules + SecureBERT + Laya + runtime testing
```

This directly measures whether each component adds value.

---

# 33. Laya Fine-Tuning

Do not fine-tune Laya before TRACEBench contains real trajectories.

First:

```text
Laya base
```

Evaluate on:

```text
held-out TRACEBench
```

Then create:

```text
TRACE-Laya
```

for decisions:

```text
should_test
next_test
priority
continue
stop
```

Compare:

```text
Laya base
vs
TRACE-Laya
```

---

# 34. TRACE-Policy

Long-term model:

```text
TRACE-Policy
```

Input:

```text
endpoint features
APM features
security signals
previous tests
observations
current confidence
remaining budget
```

Output:

```text
next_test
stop
continue
priority
```

Potential models:

```text
Laya fine-tuning
XGBoost
LightGBM
small MLP
small transformer encoder
```

For the hackathon, Laya is enough.

---

# 35. Information-Gain Testing

This should become TRACE's signature behavior.

For each candidate test:

```text
estimated value
test cost
safety level
current uncertainty
```

Calculate an internal utility:

```text
test_utility =
expected_information_gain / expected_cost
```

The first version can use heuristics.

Later, train TRACE-Policy from real trajectories.

---

# 36. Semantic Fuzzing

Create:

```text
src/trace/runtime/mutations/
├── numeric.py
├── strings.py
├── ids.py
├── roles.py
├── json.py
├── urls.py
├── paths.py
└── state.py
```

Examples:

```text
user_id
→ identity mutation

role
→ role mutation

price
→ business-rule mutation

URL
→ controlled callback mutation

path
→ traversal-oriented validation

quantity
→ boundary mutation
```

This is **semantic fuzzing**, not blind random fuzzing.

---

# 37. Stateful Testing

Build:

```text
src/trace/runtime/workflows/
```

Support:

```text
login
create
capture ID
switch identity
request object
modify
delete
refund
```

Example:

```yaml
name: cross_identity_order

steps:
  - login:
      identity: user-a

  - request:
      method: POST
      path: /api/orders

  - capture:
      variable: order_id
      from: "$.id"

  - login:
      identity: user-b

  - request:
      method: GET
      path: "/api/orders/{order_id}"
```

This is what makes TRACE capable of multi-step authorization testing.

---

# 38. Security Invariants

Create:

```text
src/trace/security/invariants/
├── ownership.py
├── roles.py
├── auth.py
├── money.py
├── url.py
├── sensitive_properties.py
└── state_transition.py
```

Examples:

```text
OWNER_ONLY
ROLE_REQUIRED
AUTH_REQUIRED
SERVER_CALCULATES_MONEY
URL_ALLOWLIST
SENSITIVE_PROPERTY_SERVER_CONTROLLED
STATE_TRANSITION_REQUIRED
```

---

# 39. Business-Logic Testing

Add controlled tests for:

```text
price manipulation
negative quantity
duplicate purchase
refund > payment
state skipping
unauthorized workflow transition
object ownership
privilege escalation
```

These are especially valuable for the vending-machine benchmark.

---

# 40. Security Test Packs

Each test pack must implement:

```python
match()
propose()
execute()
evaluate()
```

Initial:

```text
authentication
BOLA
BFLA
SSRF
mass-assignment
injection
business-logic
```

---

# 41. External Tool Integration

Use adapters.

```text
src/trace/tools/
├── base.py
├── registry.py
├── semgrep.py
├── gitleaks.py
├── osv.py
├── zap.py
├── nuclei.py
├── schemathesis.py
├── nmap.py
├── ffuf.py
├── sqlmap.py
└── nikto.py
```

TRACE owns:

```text
scope
scheduling
budgets
correlation
```

The tool owns:

```text
specialized scanning
```

---

# 42. Parallel Orchestrator

Create:

```text
src/trace/orchestrator/
├── scheduler.py
├── task.py
├── dependency.py
├── budget.py
├── executor.py
└── result_merge.py
```

Execution phases:

```text
PHASE 1
repository indexing

PHASE 2
APM construction

PHASE 3
parallel static analysis

PHASE 4
candidate generation

PHASE 5
parallel controlled runtime tests

PHASE 6
cross-tool correlation

PHASE 7
targeted follow-up tests

PHASE 8
final report
```

---

# 43. Parallel Static Lane

Run concurrently:

```text
TRACE AST rules
Semgrep
SecureBERT
Gitleaks
OSV offline
OpenAPI extraction
dependency inventory
```

---

# 44. Parallel Runtime Lane

After endpoint inventory:

```text
BOLA
BFLA
auth
SSRF
Schemathesis
ZAP baseline
selected Nuclei
custom semantic mutations
```

Do not run unlimited concurrency.

---

# 45. Runtime Budget

Default:

```toml
[budget]
max_total_requests = 500
max_parallel_tools = 4
max_parallel_active_tests = 2
max_tool_runtime_seconds = 600
```

Lab profile:

```text
higher limits
```

but still bounded.

---

# 46. External Tool Safety Tiers

## Tier 0

Passive:

```text
AST
Semgrep
SecureBERT
Gitleaks
OSV offline
OpenAPI
```

## Tier 1

Controlled:

```text
BOLA
BFLA
auth
semantic mutations
controlled SSRF
stateful tests
```

## Tier 2

Active lab:

```text
ZAP active
Nuclei active templates
ffuf
sqlmap
Nmap
Nikto
```

Tier 2 requires:

```text
lab profile
local/private target
explicit user action
```

---

# 47. Tool Scope Contract

Every tool declares:

```yaml
id: zap-active

requires_target: true
destructive: true
network_scope: local-or-private
requires_lab_mode: true
max_runtime: 600
max_requests: 2000
```

The orchestrator refuses tools that violate scope.

---

# 48. Scope Guard

Default:

```text
localhost
127.0.0.1
::1
configured Docker services
```

Reject:

```text
public hosts
public IPs
unexpected DNS resolution
external redirects
unapproved proxy
```

Every adapter uses the same ScopeGuard.

---

# 49. 100% Local Runtime

After bootstrap:

```text
source code = local
APM = local
SQLite = local
LLM = local
Laya = local
SecureBERT = local
ZAP = local
Nuclei = local
reports = local
```

No telemetry.

No source upload.

No hosted vector database.

No cloud vulnerability API.

No mandatory internet.

---

# 50. Bootstrap vs Runtime

It is acceptable for setup to download:

```text
npm packages
Python dependencies
model weights
Docker images
security binaries
```

But after bootstrap:

```bash
TRACE_RUNTIME_OFFLINE=true
```

must work.

---

# 51. Models Manifest

Create:

```text
.trace/models/manifest.json
```

Record:

```text
model
version
revision
sha256
license
source
downloaded_at
```

---

# 52. Tool Manifest

Create:

```text
.trace/tools.lock
```

Record:

```text
tool
version
binary/container digest
source
license
checksum
```

Never deploy production mode against unpinned `latest` versions.

---

# 53. Dataset Manifest

Create:

```text
training/DATASET_MANIFEST.csv
```

Fields:

```text
dataset
version
source_url
license
usage_restriction
language
sample_count
redistributable
production_eligible
```

This prevents accidental inclusion of restricted benchmark data in a distributable model.

---

# 54. TRACE MCP

The MCP server should expose only these tools:

```text
trace_scan
trace_status
trace_findings
trace_explain
trace_attack_path
trace_report
trace_replay
trace_verify
```

Do not expose:

```text
arbitrary shell
source writes
patching
unscoped network tools
```

---

# 55. `trace_scan`

Input:

```json
{
  "repository": ".",
  "profile": "standard"
}
```

Output:

```json
{
  "scan_id": "trc_001",
  "status": "completed",
  "confirmed": 6,
  "potential": 11,
  "report": ".trace/reports/latest.html"
}
```

---

# 56. `trace_findings`

Returns structured findings.

Example:

```json
{
  "id": "TRC-001",
  "status": "confirmed",
  "severity": "high",
  "category": "BOLA",
  "endpoint": "GET /api/orders/{id}",
  "source": {
    "file": "src/orders.py",
    "line": 84
  }
}
```

---

# 57. `trace_explain`

Returns:

```text
attack path
static evidence
runtime evidence
reproduction reference
tool observations
confidence
```

Do not provide a source patch.

---

# 58. `trace_verify`

After a coding agent fixes a finding:

```text
trace_verify(TRC-001)
```

TRACE:

```text
re-index
rebuild APM
re-evaluate security signals
replay original test
compare observation
```

Output:

```text
FIXED
```

or:

```text
STILL_PRESENT
```

or:

```text
INCONCLUSIVE
```

---

# 59. MCP Agent Workflow

Claude Code / Codex:

```text
trace_scan
     ↓
trace_findings
     ↓
inspect source
     ↓
fix source
     ↓
run unit tests
     ↓
trace_verify
```

TRACE never edits source.

---

# 60. NPM Package

Create:

```text
@trace-security/trace
```

Primary command:

```bash
npx -y @trace-security/trace
```

Commands:

```bash
npx -y @trace-security/trace
npx -y @trace-security/trace scan
npx -y @trace-security/trace setup
npx -y @trace-security/trace setup-mcp
npx -y @trace-security/trace mcp
npx -y @trace-security/trace doctor
```

Use npm as the **distribution/integration layer**.

The security engine can remain Python internally for v1.

---

# 61. Package Layout

```text
packages/
└── trace-cli/
    ├── package.json
    ├── bin/
    │   ├── trace.js
    │   └── trace-mcp.js
    └── src/
        ├── launcher.js
        ├── mcp.js
        ├── setup.js
        └── doctor.js
```

Python core:

```text
src/trace/
```

The npm launcher starts the local Python environment.

---

# 62. Claude Code Setup

Claude Code currently supports local MCP servers.

Expected configuration:

```bash
claude mcp add trace -- npx -y @trace-security/trace mcp
```

Windows native:

```bash
claude mcp add trace -- cmd /c npx -y @trace-security/trace mcp
```

Verify:

```bash
claude mcp list
```

The exact CLI surface must be pinned to the Claude Code version tested by the team.

---

# 63. Codex Setup

Use its local stdio MCP configuration.

Conceptual command:

```bash
codex mcp add trace -- npx -y @trace-security/trace mcp
```

Verify:

```bash
codex mcp list
```

Pin the exact command used by the hackathon environment to the tested Codex CLI version.

---

# 64. Project-Local MCP Config

Optional:

```text
.mcp.json
```

Example:

```json
{
  "mcpServers": {
    "trace": {
      "command": "npx",
      "args": [
        "-y",
        "@trace-security/trace",
        "mcp"
      ]
    }
  }
}
```

Never silently modify a project's agent configuration.

Provide:

```bash
trace setup-mcp
```

which prints or creates configuration only after explicit user approval.

---

# 65. Interactive CLI

Running:

```bash
trace
```

must launch an interactive wizard.

Example:

```text
╭──────────────────────────────────────────────────────╮
│                        TRACE                        │
│     Source → Attack Path → Test → Evidence          │
╰──────────────────────────────────────────────────────╯

Repository

  Current:
  ./my-project

Detected
  Language: Python
  Framework: FastAPI
  Package manager: uv
  Docker: ✓
  OpenAPI: ✓
  Local model: ✓
  Laya: ✓

Security profile

  1. Fast
  2. Standard   ← recommended
  3. Deep
  4. Lab

[Enter] Start
```

---

# 66. Fast Profile

```text
APM
SecureBERT
internal rules
Semgrep
Gitleaks
OSV offline
```

No expensive active runtime tests.

---

# 67. Standard Profile

```text
Fast
+
HTTPX baseline
BOLA
BFLA
authentication
SSRF
mass assignment
Schemathesis
ZAP baseline
selected Nuclei
```

---

# 68. Deep Profile

```text
Standard
+
semantic fuzzing
stateful workflows
broader test packs
more Nuclei
extended runtime validation
```

---

# 69. Lab Profile

```text
Deep
+
active ZAP
selected active Nuclei
ffuf
sqlmap
Nmap
Nikto
```

Lab profile must reject non-lab public targets.

---

# 70. CLI Progress

Use Rich:

```text
Repository indexing   ████████████████████ 100%
Attack-path model     ████████████████████ 100%
Static analysis       ████████████████████ 100%
Security triage       ████████████████████ 100%
Runtime testing       ████████████████████ 100%
Evidence correlation  ████████████████████ 100%
Report generation     ████████████████████ 100%
```

Live panel:

```text
Workers
  Semgrep       RUNNING
  SecureBERT    COMPLETE
  ZAP           RUNNING
  BOLA tests    12/18
```

---

# 71. One-Screen Final Result

```text
╭──────────────────────────────────────────────────────╮
│                    TRACE COMPLETE                    │
╰──────────────────────────────────────────────────────╯

Attack surface
  Endpoints                         73
  Security paths                   31

Testing
  Static checks                     9
  Dynamic tests                    47
  Requests                        118
  External tools                    7

Findings
  Confirmed                         6
  Potential                        11

Environment
  Runtime                         LOCAL
  Network                       BLOCKED
  Models                          LOCAL

Reports
  HTML       .trace/reports/latest.html
  JSON       .trace/reports/latest.json
  SARIF      .trace/reports/latest.sarif

MCP
  READY
```

---

# 72. Finding Quality Requirement

A finding is not confirmed because:

```text
SecureBERT score = high
```

or:

```text
Laya score = high
```

or:

```text
ZAP says alert
```

A strong finding should combine:

```text
source evidence
+
APM relationship
+
security invariant
+
runtime observation
```

Tool/model output is evidence, not absolute truth.

---

# 73. Security Invariant Example

Endpoint:

```text
GET /api/orders/{id}
```

Inferred invariant:

```text
only owner can read order
```

Observed:

```text
User A owns order 17
User B requests order 17
HTTP 200
order data returned
```

Finding:

```text
CONFIRMED BOLA
```

---

# 74. Attack-Chain Detection

Represent findings as graph objects.

Example:

```text
Weak authorization
       ↓
object exposure
       ↓
privileged endpoint
       ↓
state-changing action
```

Report:

```text
Compound attack-path candidate
```

Do not automatically exploit chains.

The objective is to identify and validate, not perform uncontrolled exploitation.

---

# 75. Security Regression

Command:

```bash
trace diff HEAD~1 HEAD
```

Detect:

```text
new endpoint
removed auth
new external sink
changed ownership check
new sensitive property
new state transition
```

Then:

```bash
trace verify
```

checks previous findings.

---

# 76. Security Gate

Command:

```bash
trace gate
```

Config:

```toml
[gate]
fail_on = [
  "confirmed_high",
  "confirmed_critical"
]

fail_on_new_auth_regression = true
fail_on_new_attack_path = true
```

Exit codes:

```text
0 = pass
1 = security gate failure
2 = inconclusive
3 = configuration error
```

---

# 77. Tool Orchestration

Tool spec:

```python
class ToolSpec:
    id: str
    name: str
    version: str

    requires_target: bool
    requires_openapi: bool

    destructive: bool
    requires_lab_mode: bool

    max_runtime_seconds: int
    max_requests: int
```

Every tool becomes a scheduled task.

---

# 78. Tool Failure Policy

If a tool is unavailable:

```text
WARNING:
Semgrep unavailable.

Continuing with TRACE core.
```

If it crashes:

```text
WARNING:
ZAP failed.

Artifact:
.trace/runs/.../zap/stderr.log
```

Do not terminate the full scan.

---

# 79. Process Isolation

For every external tool:

```text
separate process
timeout
resource limits
working directory
output capture
scope verification
artifact folder
```

Do not run all external tools inside the TRACE Python process.

---

# 80. Supply Chain Locking

Create:

```text
toolchain.lock
```

Pin:

```text
tool version
container digest
binary hash
```

NPM:

```text
package-lock.json
```

Python:

```text
uv.lock
```

Models:

```text
model manifest
```

Datasets:

```text
dataset manifest
```

---

# 81. Local Lab

Create:

```text
labs/
├── vending-api/
├── callback-service/
├── docker-compose.yml
├── crapi/
└── juice-shop/
```

---

# 82. Vending API

Endpoints:

```text
POST   /api/auth/login
GET    /api/products
GET    /api/products/{id}

POST   /api/cart
POST   /api/purchase

GET    /api/orders/{id}
DELETE /api/orders/{id}

PATCH  /api/users/{id}

POST   /api/admin/refund

POST   /api/fetch-url
```

Synthetic users:

```text
user-a
user-b
admin
```

---

# 83. Controlled Vulnerabilities

Fixture should contain:

```text
BOLA
BFLA
missing authentication
SSRF
mass assignment
safe-to-test injection indicator
business-logic flaws
```

Never use real credentials or sensitive information.

---

# 84. Callback Service

Create:

```text
labs/callback-service/
```

Endpoints:

```text
GET /health
GET /callback
```

The service records:

```text
timestamp
source
method
safe metadata
```

Use it only for controlled SSRF validation.

---

# 85. Docker Lab Network

```bash
docker network create --internal trace-lab
```

Compose:

```yaml
services:
  vuln-api:
    build: ./vending-api
    ports:
      - "127.0.0.1:18080:8000"
    networks:
      - lab

  callback-service:
    build: ./callback-service
    networks:
      - lab

networks:
  lab:
    internal: true
```

Start:

```bash
docker compose -f labs/docker-compose.yml up --build -d
```

Health:

```bash
curl http://127.0.0.1:18080/health
```

---

# 86. crAPI

Repository:

https://github.com/OWASP/crAPI

Clone:

```bash
git clone https://github.com/OWASP/crAPI.git labs/crapi
```

Use its current official Docker deployment instructions.

Keep the environment isolated.

---

# 87. Juice Shop

Repository:

https://github.com/juice-shop/juice-shop

Run:

```bash
docker pull bkimminich/juice-shop
```

Then:

```bash
docker run --rm \
  -p 127.0.0.1:3000:3000 \
  --name trace-juice-shop \
  bkimminich/juice-shop
```

---

# 88. ZAP

Repository:

https://github.com/zaproxy/zaproxy

Use:

```text
baseline
```

by default.

Active scans only:

```text
lab mode
```

Example:

```bash
docker run --rm \
  --network trace-lab \
  -v "$PWD/artifacts:/zap/wrk/:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://vuln-api:8000 \
  -r zap-baseline.html
```

---

# 89. Nuclei

Repository:

https://github.com/projectdiscovery/nuclei

Repository of templates:

https://github.com/projectdiscovery/nuclei-templates

Use:

```text
technology-aware
endpoint-aware
signal-aware
```

selection.

Do not blindly execute all templates.

---

# 90. Gitleaks

Repository:

https://github.com/gitleaks/gitleaks

Use local scanning.

Never print raw secret values.

---

# 91. OSV-Scanner

Repository:

https://github.com/google/osv-scanner

Production local-only mode must use a **local/offline vulnerability database snapshot**.

Do not silently query external vulnerability APIs during a scan.

---

# 92. Semgrep

Repository:

https://github.com/semgrep/semgrep

Use:

```text
internal rules
```

for framework/security constructs.

Again:

```text
Semgrep result
≠ final finding
```

It becomes evidence.

---

# 93. Kali Adapters

Future/local lab adapters:

```text
Nmap
ffuf
sqlmap
Nikto
testssl.sh
```

Only activate in:

```text
Lab profile
```

Example:

```bash
trace scan . --profile lab --target http://127.0.0.1:18080
```

Never remove scope checking because the target is "lab."

---

# 94. TRACE Self-Test

Command:

```bash
trace self-test
```

Checks:

```text
CLI
SQLite
Tree-sitter
APM
SecureBERT
Laya
HTTPX
scope
MCP
reports
test packs
external tool adapters
```

This must be run before any hackathon demo.

---

# 95. `trace doctor`

Command:

```bash
trace doctor
```

Display:

```text
Core
  ✓ Python
  ✓ Node
  ✓ Docker
  ✓ SQLite

AI
  ✓ Laya
  ✓ SecureBERT
  ✓ Ollama
  ✓ model

Security tools
  ✓ Semgrep
  ✓ ZAP
  ✓ Nuclei
  ✓ Gitleaks
  ✓ OSV
  - Nmap
  - ffuf

MCP
  ✓ Claude config available
  ✓ Codex config available
```

---

# 96. Benchmark Plan

Run:

```bash
trace benchmark
```

Targets:

```text
TRACE vending API
OWASP Benchmark Python
SecBench.js subset
crAPI
Juice Shop
```

Record:

```text
endpoint recall
finding recall
precision
false-positive rate
runtime
requests
CPU
RAM
Laya latency
SecureBERT latency
LLM calls
tool failures
```

---

# 97. Main Experiment

Compare:

```text
Exhaustive testing
vs
TRACE adaptive testing
```

Metrics:

```text
runtime
requests
confirmed findings
missed findings
```

The primary hypothesis:

> TRACE can reduce unnecessary security tests while maintaining useful confirmed-finding recall.

Do not state a performance percentage until measured.

---

# 98. Second Experiment

Compare:

```text
LLM-only test selection
vs
Laya + LLM
```

Measure:

```text
LLM calls
latency
test count
confirmed-finding recall
```

---

# 99. Third Experiment

Compare:

```text
source only
vs
source + endpoint
vs
source + endpoint + APM
```

Measure:

```text
security classification precision
security classification recall
```

This validates the Attack-Path Model.

---

# 100. Fourth Experiment

Compare:

```text
endpoint-by-endpoint testing
vs
stateful workflow testing
```

Use intentionally multi-step vulnerable fixtures.

Measure:

```text
unique findings
missed findings
requests
time
```

---

# 101. Fifth Experiment

Security regression:

```text
secure commit
→ vulnerable commit
→ fixed commit
```

Measure:

```text
regression detection
false-positive rate
verification success
```

---

# 102. Training Commands

Prepare datasets:

```bash
trace data prepare
```

Build TRACEBench:

```bash
trace data build-tracebench
```

Validate:

```bash
trace data validate
```

Show provenance:

```bash
trace data manifest
```

Train SecureBERT:

```bash
trace model train securebert \
  --config training/manifests/securebert_trace.yaml
```

Evaluate:

```bash
trace model evaluate securebert \
  --split test
```

Train future TRACE-Laya:

```bash
trace model train laya \
  --config training/manifests/trace_laya.yaml
```

---

# 103. Dataset CLI

Implement:

```bash
trace data list
trace data download
trace data validate
trace data manifest
trace data license-report
```

This gives the team visibility into training provenance.

---

# 104. Model CLI

Implement:

```bash
trace model list
trace model doctor
trace model verify
trace model evaluate
```

Never silently download models during a production scan.

---

# 105. No Source-Code Reasoning as a Final Authority

This is a firm requirement.

Model output:

```text
candidate
```

Runtime evidence:

```text
observed behavior
```

Final finding:

```text
correlated evidence
```

The pipeline must be:

```text
model signal
+
deterministic graph
+
runtime evidence
=
finding
```

A model can suggest.

It cannot declare truth by itself.

---

# 106. Final Finding Lifecycle

```text
STATIC_SIGNAL
     ↓
CANDIDATE
     ↓
TEST_SELECTED
     ↓
TEST_EXECUTED
     ↓
OBSERVATION
     ↓
CORRELATED
     ↓
CONFIRMED / DISMISSED / INCONCLUSIVE
```

This should be visible in the database.

---

# 107. Attack Chain Lifecycle

```text
Finding A
  ↓
Finding B
  ↓
Finding C

Potential chain
```

Only report an attack chain when:

```text
graph reachability
+
state relationship
+
evidence
```

support it.

Do not automatically execute offensive chains.

---

# 108. MCP Finding Handoff

The coding agent receives:

```json
{
  "id": "TRC-001",
  "severity": "high",
  "category": "BOLA",
  "endpoint": "GET /api/orders/{id}",
  "source": {
    "file": "src/orders.py",
    "line": 84
  },
  "attack_path": [
    "GET /api/orders/{id}",
    "OrderController.get_order",
    "OrderService.get_order",
    "OrderRepository.find_by_id",
    "orders.id"
  ],
  "evidence": {
    "static": [
      "OBJECT_ID_TO_DB",
      "OWNERSHIP_CHECK_MISSING"
    ],
    "runtime": [
      "user-b-accessed-user-a-object"
    ]
  },
  "reproduction": ".trace/runs/.../reproductions/TRC-001"
}
```

TRACE does not include a patch.

---

# 109. Agent Instructions

The MCP server should communicate:

```text
TRACE is read-only with respect to application source.

Do:
- inspect finding
- inspect source
- apply your own remediation
- run tests
- call trace_verify

Do not:
- assume potential findings are confirmed
- modify TRACE artifacts as source
- disable tests
- treat model scores as proof
```

---

# 110. Reproduction

Every confirmed finding gets:

```text
.trace/runs/<scan-id>/reproductions/<finding-id>/
├── request.json
├── expected.json
├── observed.json
├── environment.json
└── metadata.json
```

---

# 111. Regression Verification

After agent remediation:

```bash
trace verify
```

Output:

```text
Previously confirmed: 6

✓ TRC-001 fixed
✓ TRC-002 fixed
✓ TRC-003 fixed
✗ TRC-004 still present
✓ TRC-005 fixed
✓ TRC-006 fixed

Security gate: FAILED
```

The coding agent continues until:

```text
6/6 fixed
```

---

# 112. Final User Flow

The user's only required action should ideally be:

```bash
npx -y @trace-security/trace
```

Then:

```text
CONNECT REPOSITORY
      ↓
AUTO-DETECT
      ↓
AUTO-SETUP
      ↓
PRESS ENTER
      ↓
FULL LOCAL SECURITY AUDIT
      ↓
REPORT
```

If MCP is configured:

```text
coding agent
      ↓
findings
      ↓
fix
      ↓
TRACE verify
```

---

# 113. Final CLI Commands

```bash
trace
trace setup
trace doctor
trace self-test
trace scan
trace findings
trace explain <id>
trace replay <id>
trace verify
trace gate
trace diff HEAD~1 HEAD
trace benchmark
trace tools list
trace tools doctor
trace testpacks list
trace data manifest
trace model doctor
trace setup-mcp
trace mcp
```

---

# 114. Production Readiness Checklist

## Architecture

```text
[ ] Attack-Path Model deterministic
[ ] SQLite persistence
[ ] scope enforcement everywhere
[ ] source read-only boundary
[ ] reproducible runtime tests
[ ] structured findings
```

## AI

```text
[ ] SecureBERT version pinned
[ ] Laya version pinned
[ ] local LLM version pinned
[ ] abstention enabled
[ ] fallback path exists
[ ] no model-only confirmations
```

## Dataset

```text
[ ] repository-level splits
[ ] license manifests
[ ] provenance preserved
[ ] TRACEBench generated
[ ] hard negatives
[ ] runtime ground truth
```

## Tools

```text
[ ] ZAP adapter
[ ] Nuclei adapter
[ ] Schemathesis adapter
[ ] Semgrep adapter
[ ] Gitleaks adapter
[ ] OSV offline adapter
[ ] optional Kali adapters
[ ] tool version lock
```

## Security

```text
[ ] local-only runtime
[ ] no source upload
[ ] no cloud LLM
[ ] no external redirects
[ ] no arbitrary shell
[ ] no source editing
[ ] synthetic credentials
[ ] lab-only active mode
```

## Agent integration

```text
[ ] MCP server
[ ] Claude Code integration
[ ] Codex integration
[ ] finding handoff
[ ] verify loop
```

---

# 115. The Core Feature That Should Define TRACE

The strongest version of TRACE is not:

```text
"Run 20 security tools."
```

It is:

```text
Understand application
        ↓
Identify possible security invariant
        ↓
Choose the most informative safe experiment
        ↓
Execute it
        ↓
Observe actual behavior
        ↓
Correlate with source
        ↓
Confirm or dismiss
```

Everything else exists to improve that loop.

---

# 116. Final Positioning

Use this language:

> **TRACE is the local security verification layer for AI-native software development. It reconstructs application attack paths, selects the most informative safe security experiments, correlates source and runtime evidence, and exposes machine-readable findings to coding agents such as Claude Code and Codex. The coding agent fixes the code; TRACE verifies the fix.**

Short version:

```text
TRACE
SOURCE → ATTACK PATH → TEST → EVIDENCE → VERIFY
```

---

# 117. Implementation Priority

## P0 — Required

```text
[1] Interactive CLI
[2] Auto repository detection
[3] APM
[4] Scope Guard
[5] Laya integration
[6] SecureBERT inference
[7] Parallel orchestration
[8] BOLA
[9] BFLA
[10] Auth
[11] SSRF
[12] Stateful workflows
[13] Semantic mutations
[14] Evidence correlation
[15] MCP
[16] Verify
[17] JSON/HTML/SARIF reports
```

## P1

```text
Semgrep
Gitleaks
OSV offline
ZAP
Nuclei
Schemathesis
Nmap
TRACEBench generator
Benchmark suite
```

## P2

```text
SecureBERT fine-tuning
Laya fine-tuning
TRACE-Policy
attack-chain engine
security regression diff
community plugins
native binary distribution
```

---

# 118. Final Acceptance Test

This entire sequence must work:

```bash
npx -y @trace-security/trace
```

TRACE:

```text
detects repository
detects framework
checks environment
checks local models
checks tools
creates .trace
builds APM
runs static analysis
runs Laya
runs SecureBERT
schedules runtime tests
runs test packs
runs applicable external tools
correlates evidence
generates report
starts MCP server when requested
```

Then:

```text
Claude Code / Codex
      ↓
receives findings
      ↓
fixes code
      ↓
TRACE verify
      ↓
PASS
```

---

# 119. Key Research Asset

The long-term moat is:

```text
TRACEBench
+
Attack-Path Model
+
Security Invariants
+
Security Test Trajectories
+
Runtime Ground Truth
+
Regression History
```

Not the LLM itself.

Models will change.

TRACE's structured security data and attack-path representation are the reusable assets.

---

# 120. Recommended Official References

## TRACE parsing / graph / runtime

Tree-sitter:
https://github.com/tree-sitter/tree-sitter

ast-grep:
https://github.com/ast-grep/ast-grep

NetworkX:
https://github.com/networkx/networkx

HTTPX:
https://github.com/encode/httpx

## Intelligence

SecureBERT 2.0:
https://github.com/cisco-ai-defense/securebert2

Laya:
https://github.com/NandhaKishorM/laya

Ollama:
https://github.com/ollama/ollama

llama.cpp:
https://github.com/ggml-org/llama.cpp

## Benchmarks / datasets

OWASP Benchmark Python:
https://github.com/OWASP-Benchmark/BenchmarkPython

SecBench.js:
https://github.com/cristianstaicu/SecBench.js

JavaScript Vulnerability Dataset:
https://github.com/jsvul/jsvul

Kaggle Source Code Vulnerability:
https://www.kaggle.com/c/source-code-vulnerability/data

CrossVul:
https://github.com/crossvul/crossvul

PrimeVul:
https://github.com/DLVulDet/PrimeVul

LLMVul:
https://github.com/Wahed08/LLMVul-Dataset

## Security tools

Semgrep:
https://github.com/semgrep/semgrep

Gitleaks:
https://github.com/gitleaks/gitleaks

OSV-Scanner:
https://github.com/google/osv-scanner

OWASP ZAP:
https://github.com/zaproxy/zaproxy

Nuclei:
https://github.com/projectdiscovery/nuclei

Nuclei templates:
https://github.com/projectdiscovery/nuclei-templates

Schemathesis:
https://github.com/schemathesis/schemathesis

Nmap:
https://github.com/nmap/nmap

ffuf:
https://github.com/ffuf/ffuf

sqlmap:
https://github.com/sqlmapproject/sqlmap

Nikto:
https://github.com/sullo/nikto

## Training targets

OWASP crAPI:
https://github.com/OWASP/crAPI

OWASP Juice Shop:
https://github.com/juice-shop/juice-shop

## Agent interoperability

OpenAI MCP:
https://developers.openai.com/api/docs/guides/agents-api/tools/mcp

Claude Code MCP:
https://docs.anthropic.com/en/docs/claude-code/mcp

NPM exec / npx:
https://docs.npmjs.com/cli/npm-exec/

---

# 121. Final Product Definition

TRACE should ultimately be thought of as:

```text
                 AI-NATIVE SECURITY VERIFICATION

             Coding Agent
                   │
                   │ writes code
                   ▼
                Application
                   │
                   ▼
                 TRACE
                   │
        ┌──────────┼──────────┐
        ▼          ▼          ▼
       Code      Runtime    History
        │          │          │
        └──────────┼──────────┘
                   ▼
              Security Proof
                   │
                   ▼
             Coding Agent
                   │
                   ▼
                 Fix
                   │
                   ▼
             TRACE Verify
```

The final product is therefore not:

> "another vulnerability scanner."

It is:

> **a local security verification layer that continuously tests whether AI-generated software satisfies security invariants.**
