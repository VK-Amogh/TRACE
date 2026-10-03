# TRACE — Detailed Implementation Plan
## Threat Reconnaissance & Attack-path Correlation Engine

**Version:** 1.0  
**Date:** 2026-10-03  
**Target:** Hackathon POC + extensible local-first security platform  
**Primary interface:** Terminal / CLI  
**Primary execution model:** Local-first, offline-capable  
**Primary test environment:** Localhost / isolated Docker labs

---

# 0. Executive Summary

TRACE is a **local-first application security analysis and validation engine**.

Its central idea is not simply "AI scans code for vulnerabilities."

TRACE reconstructs the relationship between:

```text
Source code
    ↓
Routes / endpoints
    ↓
Authentication / authorization
    ↓
Parameters and user-controlled inputs
    ↓
Function and data-flow paths
    ↓
Database / filesystem / external-network sinks
    ↓
Runtime behavior
    ↓
Security evidence
```

The system creates an **Attack-Path Model** of the application.

The model is then used to decide:

- which endpoints deserve testing;
- which security hypotheses are plausible;
- which controlled runtime test should be executed;
- what additional test is useful after observing a response;
- whether static evidence and runtime evidence agree;
- whether a finding is only a potential issue or sufficiently evidenced as confirmed.

The architecture is deliberately modular:

```text
TRACE Core
│
├── Repository Index
├── Code Parser
├── Endpoint Discovery
├── Attack-Path Graph
├── Security Signal Engine
├── Scope Guard
├── Runtime Test Engine
├── Evidence Correlator
├── Finding Store
├── Terminal UI
│
├── Local AI Provider
│
└── Test-Pack / Tool Adapter System
      ├── BOLA
      ├── BFLA
      ├── Authentication
      ├── SSRF
      ├── Injection indicators
      ├── Mass assignment
      ├── ZAP
      ├── Nuclei
      ├── Schemathesis
      ├── TruffleHog
      ├── Nmap
      ├── ffuf
      ├── sqlmap
      ├── Nikto
      └── future test packs
```

The key architectural rule is:

> **TRACE owns the understanding and orchestration layer. External tools are interchangeable test engines.**

That prevents the project from becoming a wrapper around one security scanner.

---

# 1. Product Definition

## 1.1 One-line definition

> **TRACE maps an application's attack paths from source code to runtime behavior, then uses deterministic analysis and local AI to select controlled security tests and produce evidence-backed findings.**

## 1.2 Core product flow

```text
                   ┌─────────────────────┐
                   │      REPOSITORY     │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   SOURCE INDEXER    │
                   │ Tree-sitter/AST     │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ ENDPOINT DISCOVERY  │
                   │ Express/FastAPI/etc │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   ATTACK-PATH       │
                   │      MODEL          │
                   │   NetworkX+SQLite   │
                   └──────────┬──────────┘
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
        Deterministic Signals       Local AI Planner
                 │                         │
                 └────────────┬────────────┘
                              ▼
                   ┌─────────────────────┐
                   │     TEST ENGINE     │
                   │  HTTPX + testpacks  │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   RUNTIME EVIDENCE  │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ EVIDENCE CORRELATOR │
                   └──────────┬──────────┘
                              │
                              ▼
                  ┌──────────────────────┐
                  │ FINDING + REPORT     │
                  └──────────────────────┘
```

---

# 2. What Makes TRACE Different

TRACE should not claim to have invented:

- AST parsing;
- code property graphs;
- API fuzzing;
- DAST;
- vulnerability templates;
- local LLM inference;
- security scanners.

All of those already have strong open-source implementations.

The differentiated layer is:

```text
source understanding
        +
endpoint-centric attack-path representation
        +
runtime validation
        +
evidence correlation
        +
local AI test orchestration
```

The simplest explanation to a judge:

> **"Existing tools tell you what looks suspicious in code or what looks suspicious on the wire. TRACE connects the two."**

---

# 3. The Main Architectural Concept: Attack-Path Model

Avoid calling the internal representation merely "a graph."

Internally call it the:

# Attack-Path Model (APM)

The APM is the structured representation of how a request can move through the application.

Example:

```text
GET /api/orders/{id}
        │
        ▼
OrderController.getOrder()
        │
        ▼
OrderService.getOrder()
        │
        ▼
OrderRepository.findById()
        │
        ▼
orders.id
```

Alongside:

```text
GET /api/orders/{id}
        │
        ▼
JWT Middleware
        │
        ▼
authenticated = true
```

And:

```text
{id}
  │
  ▼
database lookup
```

The system then asks:

```text
Is authentication present?
Is authorization present?
Does object ownership get checked?
Does user input reach a dangerous sink?
Does a user-controlled URL reach an outbound HTTP client?
```

This makes the graph useful rather than decorative.

---

# 4. Core Principles

## 4.1 Local-first

Default:

```text
source repository       LOCAL
SQLite                  LOCAL
graph                   LOCAL
LLM                     LOCAL
runtime target          LOCAL/LAB
reports                 LOCAL
```

No cloud API is required.

## 4.2 Deterministic-first

Static extraction must not depend on an LLM.

The LLM is used for:

- hypothesis reasoning;
- test selection;
- next-test selection;
- response interpretation;
- report wording.

## 4.3 Evidence-first

A finding should never be produced solely because an LLM says:

> "This looks vulnerable."

A finding should contain:

```text
endpoint
source file
source line
attack path
static evidence
test
runtime observation
correlation
confidence
```

## 4.4 Scope-first

No runtime tool may execute outside TRACE's target scope.

## 4.5 Plugin-first

Security checks are test packs.

This allows new tests to be added without modifying the graph engine.

## 4.6 Reproducible

Every test should be replayable from a stored scenario.

---

# 5. System Boundaries

TRACE has five major boundaries:

```text
1. Repository boundary
2. Analysis boundary
3. AI boundary
4. Runtime boundary
5. External tool boundary
```

Each boundary gets an explicit interface.

---

# 6. Repository Technology Stack

## Core language

**Python 3.12**

Why:

- strong parsing ecosystem;
- easy CLI development;
- good HTTP tooling;
- fast prototype iteration;
- simple integration with security tools;
- easy local AI integration.

---

# 7. Required Development Tools

Install:

```text
Git
Docker Desktop
WSL2 (Windows)
Python 3.12
uv
Ollama
VS Code
```

Optional:

```text
Go
Node.js
Kali Linux
```

Go is useful for Nuclei.

Node.js is required for source-based Juice Shop validation if Docker is not used.

---

# 8. Windows Development Environment

Recommended architecture:

```text
Windows
│
├── VS Code
│
├── Docker Desktop
│      └── WSL2 backend
│
└── Ubuntu WSL2
       ├── Git
       ├── Python
       ├── uv
       └── TRACE
```

---

# 9. Install WSL2

Open PowerShell as Administrator:

```powershell
wsl --install
```

Restart if requested.

Then:

```powershell
wsl --update
```

Verify:

```powershell
wsl --version
```

Launch Ubuntu:

```powershell
wsl
```

Inside Ubuntu:

```bash
uname -a
```

---

# 10. Install Linux Dependencies

Inside Ubuntu:

```bash
sudo apt update

sudo apt install -y \
  build-essential \
  curl \
  git \
  unzip \
  jq \
  ca-certificates \
  pkg-config
```

Verify:

```bash
git --version
curl --version
jq --version
```

---

# 11. Install Docker Desktop

Official:

https://docs.docker.com/desktop/setup/install/windows-install/

Recommended settings:

```text
Settings
  → General
      → Use WSL 2 based engine

Settings
  → Resources
      → WSL Integration
          → Enable Ubuntu
```

Verify in PowerShell:

```powershell
docker --version
docker compose version
```

Verify in WSL:

```bash
docker --version
docker compose version
```

---

# 12. Install uv

Official:

https://docs.astral.sh/uv/

PowerShell:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

WSL/Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Restart shell.

Verify:

```bash
uv --version
```

---

# 13. Install Git

Windows:

```powershell
winget install --id Git.Git -e --source winget
```

WSL:

```bash
sudo apt install -y git
```

Verify:

```bash
git --version
```

---

# 14. Create TRACE Repository

Linux/WSL:

```bash
mkdir -p ~/projects
cd ~/projects

mkdir trace
cd trace

git init -b main
```

PowerShell:

```powershell
mkdir $HOME\projects
cd $HOME\projects

mkdir trace
cd trace

git init -b main
```

---

# 15. Create Python Environment

```bash
uv python install 3.12
uv venv
```

Activate:

Linux/WSL:

```bash
source .venv/bin/activate
```

PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Verify:

```bash
python --version
```

Expected:

```text
Python 3.12.x
```

---

# 16. Initialize Python Project

```bash
uv init
```

Add main dependencies:

```bash
uv add \
  typer \
  rich \
  pydantic \
  pydantic-settings \
  networkx \
  httpx \
  orjson \
  tomli-w \
  tree-sitter-language-pack
```

Development dependencies:

```bash
uv add --dev \
  pytest \
  pytest-asyncio \
  ruff \
  mypy
```

Optional API testing:

```bash
uv add schemathesis
```

---

# 17. Open-Source Components

TRACE should build on mature open-source projects.

## 17.1 Tree-sitter

Repository:

https://github.com/tree-sitter/tree-sitter

Python binding:

https://github.com/tree-sitter/py-tree-sitter

Language repositories:

```text
JavaScript:
https://github.com/tree-sitter/tree-sitter-javascript

TypeScript:
https://github.com/tree-sitter/tree-sitter-typescript

Python:
https://github.com/tree-sitter/tree-sitter-python
```

For the MVP, use:

```bash
uv add tree-sitter-language-pack
```

This keeps grammar installation simpler.

### TRACE use

Tree-sitter provides:

```text
AST
symbols
functions
classes
calls
imports
decorators
source locations
```

---

# 18. ast-grep

Repository:

https://github.com/ast-grep/ast-grep

Install CLI:

```bash
uv tool install ast-grep-cli
```

Verify:

```bash
ast-grep --version
sg --version
```

Use ast-grep for structural patterns.

Examples of patterns TRACE will eventually detect:

```text
Express route registration
FastAPI decorators
Flask routes
middleware registration
SQL query construction
HTTP client usage
dangerous sinks
```

Tree-sitter remains the core parser.

ast-grep is a pattern engine.

---

# 19. NetworkX

Repository:

https://github.com/networkx/networkx

Install:

```bash
uv add networkx
```

Use:

```text
NetworkX = in-memory graph operations
SQLite   = persistent graph metadata
```

Do not add Neo4j in the MVP.

---

# 20. HTTPX

Repository:

https://github.com/encode/httpx

Already installed with:

```bash
uv add httpx
```

Use HTTPX for:

```text
baseline requests
test requests
request variants
response collection
authentication sessions
redirect control
timeouts
```

---

# 21. Schemathesis

Repository:

https://github.com/schemathesis/schemathesis

Install:

```bash
uv add schemathesis
```

Schemathesis is useful for property-based API testing.

TRACE integration:

```text
TRACE identifies important endpoint
        ↓
TRACE extracts OpenAPI operation
        ↓
Schemathesis generates cases
        ↓
TRACE imports observations
        ↓
TRACE correlates with source graph
```

Do not make Schemathesis the core of TRACE.

---

# 22. Local AI: Ollama

Repository:

https://github.com/ollama/ollama

Official:

https://ollama.com

Install the appropriate desktop/package for the operating system.

Verify:

```bash
ollama --version
```

Check local API:

```bash
curl http://localhost:11434/api/tags
```

Local API base:

```text
http://localhost:11434/api
```

Ollama also exposes an OpenAI-compatible local endpoint:

```text
http://localhost:11434/v1
```

TRACE must use local Ollama by default.

No API key should be needed for local requests.

---

# 23. Local AI: llama.cpp

Repository:

https://github.com/ggml-org/llama.cpp

Use as an alternative provider.

Architecture:

```text
LLMProvider
├── OllamaProvider
└── LlamaCppProvider
```

TRACE must not contain model-specific assumptions.

---

# 24. Model Strategy

TRACE should support:

```text
small local model
medium local model
large local code model
```

Configuration:

```toml
[ai]
provider = "ollama"
model = "qwen3-coder"
temperature = 0.1
max_tokens = 4096
```

For weaker machines, use a smaller local model.

The model can be swapped without changing the security engine.

---

# 25. The Most Important AI Rule

Do not give the LLM:

```text
the entire repository
```

Give it:

```text
endpoint
+
security slice
+
signals
+
relevant source snippets
+
previous test observations
```

Example:

```json
{
  "endpoint": {
    "method": "GET",
    "path": "/api/orders/{id}"
  },
  "auth": {
    "required": true,
    "mechanism": "jwt"
  },
  "parameters": [
    {
      "name": "id",
      "location": "path"
    }
  ],
  "graph_path": [
    "OrderController.getOrder",
    "OrderService.getOrder",
    "OrderRepository.findById"
  ],
  "security_signals": [
    "OBJECT_ID_TO_DB",
    "OWNERSHIP_CHECK_NOT_DETECTED"
  ],
  "previous_observations": []
}
```

This is the local/token-efficient architecture.

---

# 26. TRACE Repository Structure

Create exactly:

```text
trace/
│
├── pyproject.toml
├── uv.lock
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── .gitignore
├── .env.example
├── .traceignore
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── attack-path-model.md
│   ├── runtime-policy.md
│   ├── test-pack-development.md
│   ├── tool-adapters.md
│   ├── benchmark-methodology.md
│   └── local-lab.md
│
├── src/
│   └── trace/
│       ├── __init__.py
│       ├── cli.py
│       │
│       ├── config/
│       │   ├── __init__.py
│       │   ├── settings.py
│       │   ├── defaults.py
│       │   └── loader.py
│       │
│       ├── ingest/
│       │   ├── __init__.py
│       │   ├── repository.py
│       │   ├── files.py
│       │   ├── ignore.py
│       │   └── hashing.py
│       │
│       ├── parsing/
│       │   ├── __init__.py
│       │   ├── parser.py
│       │   ├── language.py
│       │   ├── symbols.py
│       │   ├── imports.py
│       │   ├── calls.py
│       │   └── locations.py
│       │
│       ├── framework/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── express.py
│       │   ├── fastapi.py
│       │   ├── flask.py
│       │   └── nestjs.py
│       │
│       ├── apm/
│       │   ├── __init__.py
│       │   ├── model.py
│       │   ├── nodes.py
│       │   ├── edges.py
│       │   ├── builder.py
│       │   ├── traversal.py
│       │   ├── slicing.py
│       │   └── serialization.py
│       │
│       ├── security/
│       │   ├── __init__.py
│       │   ├── signals.py
│       │   ├── prioritizer.py
│       │   ├── taint.py
│       │   ├── source_sink.py
│       │   └── hypotheses.py
│       │
│       ├── testpacks/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── registry.py
│       │   ├── context.py
│       │   ├── actions.py
│       │   ├── policy.py
│       │   ├── bola.py
│       │   ├── bfla.py
│       │   ├── authentication.py
│       │   ├── injection.py
│       │   ├── ssrf.py
│       │   └── mass_assignment.py
│       │
│       ├── runtime/
│       │   ├── __init__.py
│       │   ├── client.py
│       │   ├── target.py
│       │   ├── scope.py
│       │   ├── sessions.py
│       │   ├── baseline.py
│       │   ├── variants.py
│       │   ├── observations.py
│       │   ├── comparator.py
│       │   ├── replay.py
│       │   └── workflow.py
│       │
│       ├── ai/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── ollama.py
│       │   ├── llamacpp.py
│       │   ├── prompts.py
│       │   ├── planner.py
│       │   ├── schemas.py
│       │   └── context.py
│       │
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── registry.py
│       │   ├── schemathesis.py
│       │   ├── zap.py
│       │   ├── nuclei.py
│       │   ├── trufflehog.py
│       │   ├── nmap.py
│       │   ├── ffuf.py
│       │   ├── sqlmap.py
│       │   ├── nikto.py
│       │   └── parsers/
│       │
│       ├── findings/
│       │   ├── __init__.py
│       │   ├── model.py
│       │   ├── store.py
│       │   ├── correlate.py
│       │   ├── confidence.py
│       │   └── recommendations.py
│       │
│       ├── storage/
│       │   ├── __init__.py
│       │   ├── database.py
│       │   ├── schema.py
│       │   └── migrations.py
│       │
│       ├── policy/
│       │   ├── __init__.py
│       │   ├── scope.py
│       │   ├── network.py
│       │   ├── destructive.py
│       │   └── credentials.py
│       │
│       ├── output/
│       │   ├── __init__.py
│       │   ├── terminal.py
│       │   ├── json.py
│       │   ├── html.py
│       │   └── markdown.py
│       │
│       └── benchmarks/
│           ├── __init__.py
│           ├── runner.py
│           ├── metrics.py
│           └── datasets.py
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   ├── vulnerable-fastapi/
│   │   ├── vulnerable-express/
│   │   └── vulnerable-flask/
│   ├── snapshots/
│   └── policy/
│
├── labs/
│   ├── vending-api/
│   ├── callback-service/
│   ├── docker-compose.yml
│   ├── crapi/
│   └── juice-shop/
│
├── plugins/
│   ├── testpacks/
│   └── tools/
│
├── scripts/
│   ├── bootstrap.sh
│   ├── bootstrap.ps1
│   ├── check_tools.py
│   ├── benchmark.py
│   └── license_report.py
│
└── artifacts/
    ├── reports/
    ├── benchmarks/
    ├── screenshots/
    └── raw-tool-output/
```

---

# 27. CLI Design

The CLI is the main interface.

## Top-level command

```bash
trace --help
```

Commands:

```text
init
index
endpoints
apm
analyze
test
scan
findings
explain
replay
report
benchmark
tools
testpacks
lab
clean
doctor
```

---

# 28. Core Commands

## Initialize

```bash
trace init ./my-project
```

Creates:

```text
my-project/.trace/
```

with:

```text
config.toml
graph.db
cache/
runs/
reports/
```

## Index repository

```bash
trace index ./my-project
```

## Discover endpoints

```bash
trace endpoints ./my-project
```

## Inspect Attack-Path Model

```bash
trace apm ./my-project
```

## Analyze security signals

```bash
trace analyze ./my-project
```

## Test target

```bash
trace test ./my-project \
  --target http://127.0.0.1:18080
```

## Full scan

```bash
trace scan ./my-project \
  --target http://127.0.0.1:18080
```

## Findings

```bash
trace findings
```

## Explain finding

```bash
trace explain SG-001
```

## Replay test

```bash
trace replay SG-001
```

## JSON report

```bash
trace report --format json
```

## HTML report

```bash
trace report --format html
```

## Benchmark

```bash
trace benchmark ./my-project \
  --target http://127.0.0.1:18080
```

---

# 29. Doctor Command

Implement:

```bash
trace doctor
```

It checks:

```text
Python
uv
Docker
Docker Compose
Ollama
local model
Tree-sitter
Nuclei
ZAP
Schemathesis
TruffleHog
optional Kali tools
```

Example:

```text
TRACE DOCTOR

Core
  ✓ Python 3.12
  ✓ SQLite
  ✓ Tree-sitter
  ✓ NetworkX
  ✓ HTTPX

AI
  ✓ Ollama
  ✓ Model qwen3-coder

Optional tools
  ✓ ZAP
  ✓ Nuclei
  - TruffleHog
  - ffuf
  - sqlmap

Lab
  ✓ Docker
  ✓ local network
  ✓ vending API
```

---

# 30. Trace Configuration

A target can contain:

```text
.trace/
├── config.toml
├── scope.toml
├── graph.db
└── runs/
```

Example `config.toml`:

```toml
[project]
name = "vending-lab"

[ai]
provider = "ollama"
model = "qwen3-coder"
temperature = 0.1

[target]
url = "http://127.0.0.1:18080"
mode = "local"

[runtime]
max_requests = 250
concurrency = 2
rate_limit_per_second = 3
timeout_seconds = 8
max_redirects = 3
destructive_tests = false

[analysis]
max_graph_hops = 3
max_source_context_lines = 120

[tests]
enabled = [
  "authentication",
  "bola",
  "bfla",
  "injection",
  "ssrf",
  "mass-assignment"
]

[tools]
enabled = [
  "schemathesis"
]
```

---

# 31. Scope File

Create:

```text
.trace/scope.toml
```

Example:

```toml
[scope]
mode = "local"

allowed_hosts = [
  "localhost",
  "127.0.0.1",
  "::1"
]

allowed_ports = [
  3000,
  8000,
  8080,
  8888,
  18080
]

allow_private_network = false
allow_public_network = false
follow_external_redirects = false
```

This is enforced by every runtime adapter.

---

# 32. Target Scope Model

Every target becomes:

```python
Target
```

with:

```text
scheme
host
port
base_path
environment
scope_mode
```

Scope modes:

```text
local
private-lab
authorized-network
```

MVP supports:

```text
local
private-lab
```

Public-network support should not be part of the hackathon MVP.

---

# 33. Scope Enforcement

Before any runtime request:

```text
Tool/Test
  ↓
ScopeGuard
  ↓
TargetPolicy
  ↓
NetworkPolicy
  ↓
execute
```

Reject:

```text
public internet host
unexpected port
unapproved DNS result
external redirect
proxy to unapproved host
```

---

# 34. Redirect Security

This is mandatory.

A target might return:

```text
302 Location: https://example.com
```

TRACE must stop.

Likewise:

```text
127.0.0.1
   ↓
redirect
   ↓
internal.example
```

must be checked against the same scope policy.

---

# 35. Repository Ingestion

Implement:

```python
RepositoryScanner
```

Responsibilities:

1. walk repository;
2. respect `.traceignore`;
3. ignore binary files;
4. hash files;
5. detect language;
6. parse source;
7. preserve source locations;
8. write metadata to SQLite.

Default ignored directories:

```text
.git
node_modules
.venv
venv
dist
build
coverage
__pycache__
.next
target
vendor
```

---

# 36. `.traceignore`

Example:

```text
.git/
node_modules/
.venv/
dist/
build/
coverage/
*.min.js
*.map
```

Support gitignore-like syntax later.

---

# 37. Parsing Pipeline

```text
file
 ↓
language detection
 ↓
Tree-sitter parser
 ↓
AST
 ↓
symbol extraction
 ↓
call extraction
 ↓
route extraction
 ↓
source location mapping
 ↓
APM node creation
```

Every node must preserve:

```text
file
line_start
line_end
column_start
column_end
```

---

# 38. Supported Framework Adapters

## FastAPI

Detect:

```python
@app.get("/users/{id}")
@app.post("/orders")
@router.get(...)
```

Also detect:

```python
Depends(...)
Security(...)
```

and relevant authentication middleware/dependencies.

## Flask

Detect:

```python
@app.route("/users/<id>")
@app.get("/users/<id>")
```

## Express

Detect:

```javascript
app.get("/users/:id", ...)
app.post("/orders", ...)
router.get(...)
router.post(...)
```

## NestJS

Optional P1:

```typescript
@Controller("orders")
@Get(":id")
@Post()
```

---

# 39. Normalized Endpoint Model

All framework adapters output:

```python
Endpoint
```

Example:

```json
{
  "id": "ep_001",
  "method": "GET",
  "path": "/orders/{id}",
  "handler_node_id": "fn_019",
  "auth_required": true,
  "roles": ["user"],
  "parameters": [
    {
      "name": "id",
      "location": "path",
      "user_controlled": true
    }
  ],
  "database_access": true,
  "object_identifier": true,
  "state_changing": false,
  "external_network": false,
  "sensitive_data": true,
  "source": {
    "file": "src/orders.py",
    "line": 84
  }
}
```

---

# 40. Attack-Path Model Nodes

Node types:

```text
Repository
File
Module
Class
Function
Endpoint
Parameter
Middleware
AuthCheck
Role
Database
Table
Column
ExternalService
Sink
Input
Output
Test
Observation
Finding
```

---

# 41. Attack-Path Model Edges

Edges:

```text
IMPORTS
CONTAINS
CALLS
ROUTES_TO
PROTECTED_BY
ACCEPTS
FLOWS_TO
READS
WRITES
QUERIES
RETURNS
USES_ROLE
CALLS_EXTERNAL
TESTED_BY
OBSERVED_BY
CONFIRMED_BY
```

---

# 42. Graph Confidence

Each inferred edge should carry:

```text
confidence
evidence
source_location
```

Example:

```json
{
  "source": "fn_10",
  "target": "fn_11",
  "type": "CALLS",
  "confidence": 0.96,
  "evidence": {
    "file": "service.py",
    "line": 42
  }
}
```

Do not pretend static inference is perfect.

---

# 43. Call Graph MVP

Implement only reliable/simple relationships first:

```text
direct function calls
same-module calls
simple imported functions
class methods
route -> handler
```

Later:

```text
dynamic dispatch
decorator indirection
dependency injection
framework lifecycle
```

---

# 44. Reachability-Driven Analysis

Do NOT use a fixed claim such as:

> "We analyze 10% of the code."

Instead:

```text
Endpoint
   ↓
handler
   ↓
call graph
   ↓
parameters
   ↓
security middleware
   ↓
DB / external sinks
```

This produces the **security slice**.

The slice is what receives high-priority AI attention.

---

# 45. Security Signals

Create deterministic signals:

```text
AUTH_MISSING
AUTH_INCONSISTENT
OBJECT_ID_TO_DB
OWNERSHIP_CHECK_MISSING
ROLE_CHECK_MISSING
USER_INPUT_TO_QUERY
USER_URL_TO_HTTP
ADMIN_ROUTE
STATE_CHANGE
SENSITIVE_DATA
SENSITIVE_MODEL_UPDATE
EXTERNAL_CALL
FILE_PATH_FROM_USER
```

Every signal contains:

```text
signal_id
node
source location
confidence
reason
```

---

# 46. Security Hypothesis Layer

A hypothesis is not a confirmed vulnerability.

Example:

```text
Hypothesis:
Potential BOLA

Evidence:
authenticated endpoint
+
object identifier
+
database lookup
+
ownership check not detected
```

The next stage is runtime validation.

---

# 47. Test Priority

Create `priority_score`.

Example internal weights:

```text
+3 object identifier → DB
+3 user input → dangerous sink
+3 no auth signal
+2 admin route
+2 user URL → HTTP client
+2 state change
+1 sensitive data
+1 missing validation signal
```

This score only decides testing order.

Do not call it CVSS.

Do not claim that the number represents real-world exploitability.

---

# 48. Test-Packs

The test-pack system is one of the most important parts of TRACE.

Every security test implements:

```python
class SecurityTest:
    id
    name
    version

    def match(context):
        ...

    def propose(context):
        ...

    def execute(context, action):
        ...

    def evaluate(context, observations):
        ...
```

---

# 49. Test-Pack Lifecycle

```text
Discovery
   ↓
Match
   ↓
Hypothesis
   ↓
Plan
   ↓
Policy Check
   ↓
Execute
   ↓
Observe
   ↓
Evaluate
   ↓
Finding
```

---

# 50. Test-Pack Context

Every test receives:

```text
endpoint metadata
APM slice
security signals
target
test identities
previous observations
runtime policy
```

No plugin receives arbitrary unrestricted machine access.

---

# 51. Test-Pack Action Model

Allowed actions:

```text
RUN_REQUEST
CHANGE_PATH_PARAMETER
CHANGE_QUERY_PARAMETER
CHANGE_JSON_FIELD
REMOVE_AUTH_HEADER
CHANGE_AUTH_CONTEXT
REPLAY_REQUEST
COMPARE_RESPONSE
STOP
```

LLM output must match a Pydantic schema.

---

# 52. AI Structured Planner

Example:

```json
{
  "decision": "RUN_TEST",
  "test_id": "bola",
  "action": {
    "type": "CHANGE_AUTH_CONTEXT",
    "identity": "user-b"
  },
  "reason": "The endpoint accepts an object identifier and the security slice does not show an ownership constraint."
}
```

TRACE validates:

```text
schema
+
test exists
+
action allowed
+
target allowed
+
identity exists
```

Only then is the test executed.

---

# 53. Never Allow LLM Shell Execution

Forbidden architecture:

```text
LLM
 ↓
shell command
 ↓
anything
```

Allowed:

```text
LLM
 ↓
structured action
 ↓
validator
 ↓
test-pack
 ↓
HTTPX / approved tool adapter
```

The local model must never be able to:

```text
execute arbitrary shell
modify source
delete files
scan arbitrary hosts
download arbitrary files
start arbitrary network listeners
```

---

# 54. Initial Test-Packs

Implement in this order:

```text
1. authentication
2. BOLA
3. BFLA
4. mass-assignment
5. SSRF
6. injection indicators
```

---

# 55. Authentication Test-Pack

Static:

```text
sensitive endpoint
+
no auth middleware
```

Runtime:

```text
baseline authenticated
vs
anonymous
```

Evidence:

```text
status
body
returned object
```

---

# 56. BOLA Test-Pack

Static signals:

```text
authenticated endpoint
+
object identifier
+
database object lookup
+
ownership check missing/not detected
```

Lab runtime:

```text
User A owns object A
User B requests object A
```

Observe:

```text
status
object fields
ownership
```

Only mark confirmed if the fixture's expected ownership boundary is violated.

---

# 57. BFLA Test-Pack

Lab contains:

```text
anonymous
user
admin
```

Test:

```text
user
 ↓
admin endpoint
```

Evidence:

```text
expected rejection
vs
observed success
```

---

# 58. Mass-Assignment Test-Pack

Static:

```text
request body
 ↓
model update/create
 ↓
sensitive property
```

Runtime should use a synthetic field in the fixture, not real sensitive data.

Example:

```text
role
is_admin
credit_limit
```

only inside the deliberately vulnerable lab.

---

# 59. SSRF Test-Pack

Use a controlled callback service.

Architecture:

```text
TRACE
  |
  v
vulnerable-api
  |
  v
callback-service
```

The callback service records incoming requests.

No third-party host is needed.

---

# 60. Injection Test-Pack

MVP objective:

```text
detect user-input → sink relationship
+
perform harmless runtime validation
```

Do not make destructive database/file-system operations part of the default scan.

For advanced lab-only testing, use external specialized adapters under explicit policy.

---

# 61. Future Test-Packs

Design for:

```text
path traversal
file upload
CORS
CSRF
open redirect
rate-limit behavior
security headers
GraphQL
WebSocket
deserialization indicators
dependency risks
secret detection
TLS checks
```

Each is added as a plugin.

---

# 62. Tool Adapter System

External tools are not test-pack implementations.

They are adapters.

Structure:

```text
tools/
├── base.py
├── registry.py
├── schemathesis.py
├── zap.py
├── nuclei.py
├── trufflehog.py
├── nmap.py
├── ffuf.py
├── sqlmap.py
└── nikto.py
```

---

# 63. Tool Adapter Contract

```python
class ToolAdapter:
    id
    name
    version

    def available():
        ...

    def validate_target():
        ...

    def build_command():
        ...

    def run():
        ...

    def parse_results():
        ...
```

Every adapter must invoke the same scope policy.

---

# 64. OWASP ZAP Adapter

Repository:

https://github.com/zaproxy/zaproxy

Use first:

```text
baseline/passive
```

Then later:

```text
API scan
authenticated scan
active lab scan
```

Docker image:

```text
ghcr.io/zaproxy/zaproxy:stable
```

Example isolated-lab invocation:

```bash
docker run --rm \
  --network secgraph-lab \
  -v "$PWD/artifacts:/zap/wrk/:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://vuln-api:8000 \
  -r zap-baseline.html
```

Do not point this at systems you are not explicitly authorized to test.

---

# 65. Nuclei Adapter

Repository:

https://github.com/projectdiscovery/nuclei

Install with Go:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Verify:

```bash
nuclei -version
```

TRACE should initially run only selected templates against the isolated target.

The adapter should:

```text
scope check
 ↓
selected templates
 ↓
JSON output
 ↓
parser
 ↓
Finding model
```

Nuclei is template-driven and extensible, making it a good external test engine.

---

# 66. TruffleHog Adapter

Repository:

https://github.com/trufflesecurity/trufflehog

Local filesystem example:

```bash
docker run --rm -it \
  -v "$PWD:/pwd" \
  trufflesecurity/trufflehog:latest \
  filesystem /pwd
```

TRACE should redact secret values.

Store:

```text
type
file
line
verification status
redacted preview
```

Never print credential values.

---

# 67. Nmap Adapter

Repository:

https://github.com/nmap/nmap

Nmap is an optional network-level adapter.

Use only inside explicitly authorized local/private lab scope.

For the hackathon:

```text
TRACE
 ↓
scope guard
 ↓
local target
 ↓
Nmap
 ↓
ports/services
 ↓
finding context
```

Do not allow arbitrary internet host input.

---

# 68. ffuf Adapter

Repository:

https://github.com/ffuf/ffuf

Use as a future content-discovery test engine.

Appropriate use:

```text
localhost
private lab
synthetic app
```

TRACE can provide a discovered route prefix and import discovered paths.

The adapter must enforce:

```text
scope
rate
request cap
```

---

# 69. sqlmap Adapter

Repository:

https://github.com/sqlmapproject/sqlmap

Do not execute automatically in the default TRACE scan.

Use as:

```text
explicit lab-only advanced test
```

Workflow:

```text
TRACE detects strong injection hypothesis
        ↓
user explicitly enables advanced SQL test
        ↓
scope verification
        ↓
sqlmap adapter
        ↓
structured results
```

The default product remains non-destructive.

---

# 70. Nikto Adapter

Repository:

https://github.com/sullo/nikto

Use as a future HTTP misconfiguration scanner.

Only:

```text
local
private lab
authorized scope
```

---

# 71. Kali Linux Integration

Kali should be considered a **tool execution environment**, not part of the TRACE core.

Architecture:

```text
TRACE
   |
   +-- native tests
   |
   +-- Python integrations
   |
   +-- tool adapters
             |
             +-- Nmap
             +-- ffuf
             +-- sqlmap
             +-- Nikto
             +-- testssl.sh
             +-- other lab tools
```

This allows you to add community/hacker-developed tooling over time.

---

# 72. Kali Isolated Environment

Use a dedicated VM or container.

For a containerized lab:

```bash
docker run --rm -it \
  --network secgraph-lab \
  kalilinux/kali-rolling \
  /bin/bash
```

Inside:

```bash
apt update
apt install -y \
  nmap \
  ffuf \
  nikto \
  sqlmap
```

This environment is optional.

Do not mount:

```text
~/.ssh
cloud credentials
password stores
production source
browser profiles
```

into the container.

---

# 73. External Test-Packs: Three Safety Tiers

This is a useful future architecture.

## Tier 0 — Passive

Examples:

```text
source analysis
OpenAPI analysis
secret detection
HTTP headers
fingerprinting
```

No state change.

## Tier 1 — Controlled validation

Examples:

```text
authorization boundary tests
safe type changes
anonymous/authenticated comparison
synthetic SSRF callback
non-destructive fuzzing
```

Allowed by default on local labs.

## Tier 2 — Active lab-only

Examples:

```text
heavy fuzzing
sqlmap
aggressive Nuclei templates
active ZAP
large ffuf runs
network enumeration
```

Requires:

```text
explicit lab mode
scope confirmation
```

This makes the project extensible without making the default product dangerous.

---

# 74. Lab Mode

CLI:

```bash
trace scan ./labs/vending-api \
  --target http://127.0.0.1:18080 \
  --mode lab
```

For an advanced tool:

```bash
trace tool run sqlmap \
  --target http://127.0.0.1:18080 \
  --lab
```

The adapter still verifies the target.

---

# 75. Lab Target Marker

Require deliberately created targets to include:

```text
X-TRACE-LAB: true
```

or configuration metadata.

Example:

```toml
[target]
mode = "lab"
label = "trace-vending"
lab_marker = "trace-vending-v1"
```

The runtime target adapter can verify the target before running Tier 2 tests.

This is an additional safety layer for the demo environment.

---

# 76. Vending-Machine Lab

Create:

```text
labs/vending-api/
├── app/
│   ├── main.py
│   ├── auth.py
│   ├── db.py
│   ├── models.py
│   ├── routes/
│   │   ├── auth.py
│   │   ├── products.py
│   │   ├── orders.py
│   │   ├── users.py
│   │   ├── admin.py
│   │   └── fetch.py
│   └── seed.py
├── tests/
├── Dockerfile
├── requirements.txt
└── README.md
```

---

# 77. Vending API Endpoints

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

---

# 78. Vending Lab Identities

Create only synthetic accounts:

```text
user-a
user-b
admin
```

Passwords:

```text
local-test-password
```

Never reuse real credentials.

---

# 79. Intentionally Vulnerable Behaviors

The fixture should intentionally include:

```text
BOLA:
object lookup without ownership enforcement

BFLA:
admin endpoint with flawed role validation

Auth:
sensitive endpoint missing authentication

SSRF:
user-controlled URL sent to callback-service

Mass assignment:
request body mapped to sensitive model fields

Injection indicator:
unsafe string construction around synthetic database query
```

These exist only to test TRACE.

---

# 80. Callback Service

Create:

```text
labs/callback-service/
├── main.py
├── Dockerfile
└── README.md
```

Endpoints:

```text
GET /health
GET /callback
```

Record:

```text
timestamp
method
source container
safe request metadata
```

No real secret collection.

---

# 81. Isolated Docker Network

Create:

```bash
docker network create --internal secgraph-lab
```

The `--internal` network should be used for the security lab.

---

# 82. Lab Docker Compose

Create:

```text
labs/docker-compose.yml
```

Example:

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

---

# 83. Start Lab

```bash
docker compose -f labs/docker-compose.yml up --build -d
```

Check:

```bash
docker compose -f labs/docker-compose.yml ps
```

Health:

```bash
curl http://127.0.0.1:18080/health
```

Stop:

```bash
docker compose -f labs/docker-compose.yml down
```

Reset:

```bash
docker compose -f labs/docker-compose.yml down -v
docker compose -f labs/docker-compose.yml up --build -d
```

---

# 84. OWASP crAPI

Repository:

https://github.com/OWASP/crAPI

Current project documentation includes a Docker Compose setup.

Clone:

```bash
git clone https://github.com/OWASP/crAPI.git labs/crapi
```

Move into Docker deployment:

```bash
cd labs/crapi/deploy/docker
```

Pull:

```bash
docker compose pull
```

Start:

```bash
docker compose -f docker-compose.yml --compatibility up -d
```

The current documentation exposes crAPI on:

```text
http://localhost:8888
```

crAPI is deliberately vulnerable and is an appropriate authorized test target.

Keep it isolated from unrelated services.

---

# 85. OWASP Juice Shop

Repository:

https://github.com/juice-shop/juice-shop

Docker:

```bash
docker pull bkimminich/juice-shop
```

Run loopback-only:

```bash
docker run --rm \
  -p 127.0.0.1:3000:3000 \
  --name juice-shop \
  bkimminich/juice-shop
```

Then:

```text
http://127.0.0.1:3000
```

Source-based setup:

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git labs/juice-shop
cd labs/juice-shop
npm install
npm start
```

Docker is preferred for hackathon repeatability.

---

# 86. Why Use Three Lab Targets

## Target 1 — vending-api

Purpose:

```text
full control
known expected findings
benchmark
unit/integration testing
```

## Target 2 — crAPI

Purpose:

```text
realistic API security validation
microservice behavior
complexity
```

## Target 3 — Juice Shop

Purpose:

```text
different architecture
Node.js / Express
broader web application behavior
```

A strong hackathon demo uses all three.

---

# 87. Local-Only Execution

Environment variable:

```bash
TRACE_LOCAL_ONLY=true
```

Behavior:

```text
block public hosts
block public IPs
block external redirects
limit DNS resolution
limit ports
require local/private lab scope
```

---

# 88. Runtime Request Limits

Default:

```text
max requests             250
concurrency                2
rate                       3/sec
timeout                    8 sec
redirects                  3
destructive tests        false
```

Advanced lab profile:

```text
max requests             2000
concurrency                4
```

Only with:

```text
mode = lab
```

---

# 89. Request Logging

Store:

```text
method
path
safe headers
body hash
timestamp
test id
```

Do not store:

```text
raw passwords
API tokens
cookies containing credentials
secret values
```

Redact:

```text
Authorization
Cookie
Set-Cookie
X-API-Key
password
token
secret
```

---

# 90. Authentication Sessions

Create:

```python
TestIdentity
```

Fields:

```text
name
role
auth_headers
cookies
metadata
```

Example:

```text
anonymous
user-a
user-b
admin
```

Plugins can switch identities through the runtime engine.

---

# 91. Baseline Request

For every endpoint:

```text
construct baseline
 ↓
execute
 ↓
capture observation
```

Observation:

```json
{
  "status": 200,
  "content_type": "application/json",
  "size": 843,
  "json_shape": {
    "id": "integer",
    "owner_id": "integer"
  }
}
```

---

# 92. Runtime Variants

Initial harmless variations:

```text
anonymous
authenticated
other test identity
missing field
extra field
invalid type
boundary numeric value
empty value
null
duplicate value
```

The set is endpoint-aware.

Do not send every variation to every endpoint.

---

# 93. Response Comparator

Compare:

```text
status
content type
JSON structure
selected JSON fields
body size
error category
redirect
```

Use structural comparison.

Do not use naive full-body string comparison as the primary mechanism.

---

# 94. Evidence Model

Every observation becomes:

```python
Observation
```

Containing:

```text
test_id
timestamp
request
response
identity
environment
source_endpoint
```

Every evidence item contains:

```text
type
source
description
confidence
```

---

# 95. Finding Status

Use:

```text
POTENTIAL
CONFIRMED
DISMISSED
```

Logic:

```text
static evidence only
    ↓
POTENTIAL

static evidence
+
runtime evidence supporting it
    ↓
CONFIRMED

runtime result contradicts hypothesis
    ↓
DISMISSED
```

---

# 96. Finding Severity

Keep severity separate from confidence.

Example:

```text
severity = HIGH
confidence = 0.94
status = CONFIRMED
```

The LLM may assist with classification but the report must preserve:

```text
evidence
basis
uncertainty
```

Do not present an LLM-generated severity as objective truth.

---

# 97. Example Finding

```text
HIGH / CONFIRMED

SG-003
BOLA

Endpoint:
GET /api/orders/{id}

Source:
src/routes/orders.py:84

Attack path:
Endpoint
 → Auth dependency
 → OrderController.get_order
 → OrderService.get_order
 → OrderRepository.find_by_id
 → orders.id

Static evidence:
- authenticated endpoint
- user-controlled object identifier
- database lookup
- ownership constraint not detected

Runtime evidence:
- User A accessed own object
- User B requested the same object
- object data was returned

Conclusion:
The lab application exposed an object belonging
to another test identity without an ownership check.

Recommendation:
Enforce object ownership before returning the record.
```

---

# 98. AI Prompt Architecture

Do not create a single giant prompt.

Use:

```text
prompts/
├── classify_endpoint.md
├── analyze_auth.md
├── generate_hypothesis.md
├── choose_test.md
├── interpret_observation.md
├── determine_next_test.md
└── explain_finding.md
```

---

# 99. AI Context Pipeline

```text
endpoint
 ↓
retrieve APM slice
 ↓
retrieve source snippets
 ↓
retrieve security signals
 ↓
retrieve observations
 ↓
build structured prompt
 ↓
local model
 ↓
Pydantic schema
 ↓
policy validator
```

---

# 100. LLM Output Schema

Example:

```json
{
  "decision": "RUN_TEST",
  "test_id": "bola",
  "action": {
    "type": "CHANGE_AUTH_CONTEXT",
    "identity": "user-b"
  },
  "reason": "The endpoint exposes an object identifier and the graph does not show an ownership check."
}
```

Valid decisions:

```text
RUN_TEST
STOP
REQUEST_MORE_STATIC_CONTEXT
REQUEST_BASELINE
```

---

# 101. Local AI Fallback

If Ollama is unavailable:

```text
TRACE analyze
```

must still work in deterministic mode.

Output:

```text
AI unavailable
Running deterministic analysis only.
```

This is critical for hackathon reliability.

---

# 102. APM Retrieval

For endpoint `E`:

```python
security_slice = get_security_slice(
    endpoint_id=E,
    max_hops=3
)
```

Include:

```text
endpoint
handler
middleware
parameters
direct callees
database sinks
external sinks
relevant security checks
```

Do not serialize the full graph.

---

# 103. SQLite Schema

Tables:

## repositories

```text
id
path
name
hash
created_at
```

## files

```text
id
repository_id
path
language
hash
size
```

## nodes

```text
id
repository_id
type
name
file_id
line_start
line_end
metadata_json
```

## edges

```text
id
source_id
target_id
type
confidence
evidence_json
```

## endpoints

```text
id
node_id
method
path
auth_required
roles
metadata_json
```

## signals

```text
id
endpoint_id
type
confidence
evidence_json
```

## tests

```text
id
endpoint_id
test_id
request_json
response_json
status
created_at
```

## findings

```text
id
type
severity
confidence
status
endpoint_id
evidence_json
created_at
```

---

# 104. Persistence Strategy

SQLite is authoritative.

NetworkX is runtime representation.

Flow:

```text
SQLite
  ↓
load graph
  ↓
NetworkX
  ↓
analysis
  ↓
persist updates
```

This is simpler than deploying a graph database.

---

# 105. Tool Output Normalization

Every external tool output must be converted to:

```text
ToolObservation
```

Fields:

```text
tool
tool_version
target
timestamp
raw_artifact_path
normalized_result
```

Then:

```text
ToolObservation
        ↓
Evidence Correlator
        ↓
Finding
```

---

# 106. Tool Failure Handling

If a tool is absent:

```text
skip tool
continue core scan
```

If tool fails:

```text
capture failure
mark tool unavailable
continue
```

Do not crash the entire scan because ZAP is not installed.

---

# 107. `trace tools`

Implement:

```bash
trace tools list
trace tools doctor
trace tools enable nuclei
trace tools disable nuclei
```

Example:

```text
TRACE TOOLCHAIN

Core
 ✓ HTTPX
 ✓ Tree-sitter

Local AI
 ✓ Ollama

Security tools
 ✓ ZAP
 ✓ Nuclei
 - Nmap
 - ffuf
 - sqlmap
```

---

# 108. `trace testpacks`

Implement:

```bash
trace testpacks list
trace testpacks info bola
trace testpacks enable bola
trace testpacks disable injection
```

This creates a clean extension story.

---

# 109. External Plugin Packaging

Future test pack:

```text
plugins/testpacks/trace-test-graphql
```

Manifest:

```yaml
id: graphql
name: GraphQL Security Tests
version: 0.1.0

scope:
  default_mode: local
  destructive: false

requires:
  - trace>=0.1
```

The plugin exposes:

```text
match()
propose()
evaluate()
```

---

# 110. Test Pack Safety Policy

Every test pack declares:

```text
destructive: true/false
network_level: none/local/private
max_requests
```

Examples:

```yaml
id: bola
destructive: false
network_level: local
```

Advanced pack:

```yaml
id: sqlmap-lab
destructive: true
network_level: local
requires_mode: lab
```

The policy engine enforces this.

---

# 111. Future Security Test Ecosystem

TRACE should eventually support:

```text
TRACE Test Packs
│
├── API
│   ├── BOLA
│   ├── BFLA
│   ├── auth
│   ├── mass assignment
│   ├── schema bypass
│   └── rate-limit
│
├── Web
│   ├── XSS indicators
│   ├── CSRF
│   ├── CORS
│   ├── path traversal
│   ├── upload
│   └── redirect
│
├── Network
│   ├── Nmap
│   ├── TLS
│   └── service exposure
│
├── Infrastructure
│   ├── headers
│   ├── container configuration
│   └── secrets
│
└── Advanced Lab
    ├── ffuf
    ├── sqlmap
    ├── ZAP active
    └── selected Nuclei templates
```

---

# 112. Why This Is Better Than "Add Every Kali Tool"

Do not build:

```text
TRACE = Nmap + ZAP + Nuclei + SQLMap + ffuf + AI
```

That would be a wrapper.

Build:

```text
TRACE
  = Attack-Path Model
  + scope
  + test planning
  + evidence correlation
  + tool orchestration
```

Then tools are interchangeable.

---

# 113. First Development Milestone

The first end-to-end success criterion:

```bash
trace scan ./labs/vending-api \
  --target http://127.0.0.1:18080
```

It must produce:

```text
files
functions
endpoints
APM nodes
APM edges
security signals
test plan
runtime observations
findings
```

If that works, the architecture works.

---

# 114. Implementation Order

Do not implement everything in parallel.

## Step 1 — Bootstrap

Create:

```text
pyproject.toml
CLI
configuration
logging
SQLite
```

Acceptance:

```bash
trace --help
```

---

## Step 2 — Doctor

Implement:

```bash
trace doctor
```

It checks the machine.

---

## Step 3 — Repository Ingestion

Implement:

```bash
trace index .
```

Output:

```text
Files
Languages
LOC
Hash
```

---

## Step 4 — Tree-sitter

Extract:

```text
files
functions
classes
imports
calls
decorators
locations
```

Acceptance:

```text
all extracted objects have valid source coordinates
```

---

## Step 5 — Framework Adapters

Implement:

```text
FastAPI
Express
Flask
```

Acceptance:

```bash
trace endpoints .
```

returns normalized endpoints.

---

## Step 6 — APM

Build:

```text
nodes
edges
SQLite
NetworkX traversal
```

Acceptance:

```bash
trace apm .
```

shows attack paths.

---

## Step 7 — Security Signals

Implement:

```text
AUTH_MISSING
OBJECT_ID_TO_DB
OWNERSHIP_CHECK_MISSING
ROLE_CHECK_MISSING
USER_INPUT_TO_QUERY
USER_URL_TO_HTTP
SENSITIVE_MODEL_UPDATE
```

---

## Step 8 — Security Prioritizer

Rank endpoints.

Do not test every endpoint equally.

---

## Step 9 — Scope Guard

Implement before runtime tests.

Test:

```text
localhost
127.0.0.1
public host
public IP
external redirect
wrong port
```

---

## Step 10 — HTTPX Runtime

Implement:

```text
baseline
session
request
response
comparison
logging
```

---

## Step 11 — Test Packs

Order:

```text
authentication
BOLA
BFLA
mass-assignment
SSRF
injection
```

---

## Step 12 — Ollama

Implement:

```text
LLMProvider
OllamaProvider
structured output
planner
```

---

## Step 13 — Evidence Correlation

Implement:

```text
static + runtime
    ↓
finding
```

---

## Step 14 — Reports

Implement:

```text
terminal
JSON
HTML
Markdown
```

---

## Step 15 — External Tools

Add:

```text
Schemathesis
ZAP
Nuclei
TruffleHog
Nmap
ffuf
sqlmap
Nikto
```

one at a time.

---

## Step 16 — crAPI

Validate without special-casing.

---

## Step 17 — Juice Shop

Validate a different codebase and framework.

---

## Step 18 — Benchmark

Measure everything.

---

# 115. Terminal Output

Example:

```text
╭─────────────────────────────────────────────────────╮
│                     TRACE SCAN                      │
│ Threat Reconnaissance & Attack-path Correlation     │
╰─────────────────────────────────────────────────────╯

Repository
  Files                              842
  Functions                        5,291
  Endpoints                           73

Attack-Path Model
  Nodes                           18,293
  Edges                           41,020
  Security slices                    19

AI
  Provider                         Ollama
  Model                      qwen3-coder
  Mode                              local

Security hypotheses
  Authentication                      4
  BOLA                                8
  BFLA                                3
  SSRF                                2
  Injection                           5

Runtime
  Candidate tests                    41
  Executed tests                     41
  Requests                           87

Findings
  Confirmed                           7
  Potential                          11
```

Numbers above are illustrative only. TRACE must display actual measured values in real runs.

---

# 116. Finding Output

Example:

```text
HIGH / CONFIRMED
SG-003

BOLA

GET /api/orders/{id}

Source:
src/orders/controller.py:84

Attack path:
Endpoint
  ↓
Auth
  ↓
Controller
  ↓
Service
  ↓
Repository
  ↓
orders.id

Static evidence:
✓ authentication present
✓ object identifier detected
✓ database lookup detected
? ownership check not detected

Runtime:
User A owns object 17
User B requests object 17
Response = 200
Object data returned

Status:
CONFIRMED

Recommendation:
Enforce object ownership before returning the record.
```

---

# 117. Replay System

Every finding should be replayable.

Command:

```bash
trace replay SG-003
```

Output:

```text
Loading stored scenario...
Checking target scope...
Running baseline...
Running test...
Comparing...
Result reproduced.
```

This is important for judge demonstrations.

---

# 118. Evidence Artifact Directory

Each scan:

```text
.trace/runs/<run-id>/
├── scan.json
├── endpoints.json
├── signals.json
├── tests.json
├── observations.json
├── findings.json
├── prompts/
├── tool-output/
└── report.html
```

This makes demos reproducible.

---

# 119. Secrets Policy

Never store:

```text
real passwords
real access tokens
cloud API keys
SSH keys
browser cookies
```

Test fixtures must use synthetic credentials.

---

# 120. Redaction

Implement a central:

```text
SecretRedactor
```

Patterns:

```text
Authorization
Cookie
Set-Cookie
X-API-Key
password
token
secret
private_key
```

Everything gets redacted before:

```text
logging
LLM context
reporting
artifact storage
```

---

# 121. Benchmark Methodology

Create:

```bash
trace benchmark ./labs/vending-api \
  --target http://127.0.0.1:18080
```

Measure:

```text
repository files
LOC
AST objects
APM nodes
APM edges
endpoints
security slices
candidate tests
executed tests
requests
scan duration
peak memory
CPU
LLM calls
LLM tokens
confirmed findings
potential findings
false positives
```

---

# 122. Main Benchmark Experiment

Compare:

## Mode A — Exhaustive

Every endpoint receives every applicable test.

## Mode B — TRACE prioritized

Only high-priority attack paths receive expensive tests.

Compare:

```text
requests
runtime
LLM calls
findings
confirmed findings
```

The hypothesis:

> TRACE can reduce unnecessary testing by prioritizing security-relevant attack paths.

Do not claim a numerical improvement before measuring it.

---

# 123. Graph Coverage Metrics

Measure:

```text
endpoint discovery recall
call graph edge precision
security slice size
database-flow coverage
auth-flow coverage
```

For the fixture, the "ground truth" is manually declared.

---

# 124. AI Metrics

Measure:

```text
test selection accuracy
response interpretation accuracy
next-test usefulness
false-positive reduction
tokens per endpoint
latency
```

Run:

```text
deterministic-only
```

against:

```text
deterministic + local AI
```

This is a strong hackathon experiment.

---

# 125. Test Fixtures

Create known vulnerabilities.

For each fixture:

```text
known vulnerable
known safe
```

Store expected:

```text
endpoints
signals
finding classes
```

Golden files:

```text
tests/snapshots/
├── vending-endpoints.json
├── vending-apm.json
├── vending-signals.json
└── vending-findings.json
```

---

# 126. Unit Tests

Minimum:

```text
test_file_scanner
test_language_detection
test_tree_sitter
test_source_locations
test_fastapi_routes
test_express_routes
test_flask_routes
test_call_graph
test_apm_build
test_apm_slice
test_scope_guard
test_redirect_guard
test_httpx_client
test_response_comparator
test_auth_test
test_bola_test
test_bfla_test
test_ssrf_test
test_mass_assignment_test
test_finding_correlation
test_llm_schema_validation
```

Run:

```bash
uv run pytest
```

---

# 127. Linting

Run:

```bash
uv run ruff check .
uv run ruff format --check .
```

Fix:

```bash
uv run ruff check . --fix
uv run ruff format .
```

---

# 128. Type Checking

```bash
uv run mypy src
```

---

# 129. Git Workflow

Branches:

```text
main
develop
feature/indexer
feature/apm
feature/runtime
feature/ai
feature/testpacks
feature/tool-adapters
```

Commit style:

```text
feat(cli): add scan command
feat(apm): add endpoint attack paths
feat(runtime): add scope guard
feat(ai): add Ollama provider
feat(testpack): add BOLA validation
feat(tool): add ZAP adapter
```

---

# 130. CI

Create:

```text
.github/workflows/
├── test.yml
├── lint.yml
└── security.yml
```

Run:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src
```

---

# 131. Dockerizing TRACE

After native execution works:

```text
docker/
├── Dockerfile
└── docker-compose.yml
```

Do not bundle a large model inside TRACE's image initially.

Keep:

```text
TRACE container
      |
      v
Ollama host
```

Later, an all-in-one local deployment can be added.

---

# 132. Offline Capability

The normal local scan should work without internet after dependencies and model are installed.

Preload:

```text
Python dependencies
Tree-sitter grammars
Ollama model
optional Docker images
```

Then disconnect network.

Run:

```bash
trace scan ...
```

If it still works, the local-first claim is real.

---

# 133. Optional Offline Model Setup

Create:

```text
scripts/preload-model.sh
```

Example:

```bash
ollama pull qwen3-coder
```

Exact model selection should depend on available RAM/VRAM.

---

# 134. Tool Availability Policy

Commands:

```bash
trace tools list
trace tools doctor
```

Missing tool:

```text
WARNING: sqlmap not installed
Continuing with core engine.
```

Tool failure:

```text
WARNING: Nuclei adapter failed.
Core scan continues.
```

No single external tool is allowed to take down TRACE.

---

# 135. Plugin API Versioning

Every plugin declares:

```text
api_version
plugin_version
```

Example:

```yaml
id: bola
version: 0.1.0
api_version: 1
```

This enables future external test packs.

---

# 136. Future Community Architecture

Eventually:

```text
TRACE Marketplace / Registry
         |
         +-- API test packs
         +-- Graph rules
         +-- tool adapters
         +-- framework adapters
```

But the hackathon should only implement local plugin loading.

---

# 137. Local Plugin Loading

Example:

```text
plugins/testpacks/bola-custom/
├── manifest.yaml
└── plugin.py
```

CLI:

```bash
trace testpacks install ./plugins/testpacks/bola-custom
```

The plugin is validated before activation.

---

# 138. Plugin Permissions

Future manifest:

```yaml
permissions:
  source_read: true
  network_local: true
  network_private: false
  shell: false
  filesystem_write: false
```

This is a strong long-term differentiator.

---

# 139. Security Model of TRACE

Treat TRACE plugins as untrusted code.

Default:

```text
source read
local HTTP test
no shell
no arbitrary write
```

Advanced plugins should run in containers or sandboxes.

---

# 140. Test-Packs vs Tool Adapters

Keep the distinction:

## Test-Pack

Understands a security behavior.

Example:

```text
BOLA
SSRF
BFLA
```

## Tool Adapter

Calls an external engine.

Example:

```text
ZAP
Nuclei
Nmap
ffuf
sqlmap
```

This separation is critical.

---

# 141. Architecture with Both Layers

```text
                         TRACE
                           │
                 ┌─────────┴─────────┐
                 │                   │
              Test-Packs         Tool Adapters
                 │                   │
        ┌────────┼────────┐     ┌────┼─────┐
       BOLA     SSRF     BFLA   ZAP Nuclei Nmap
        │        │        │      │     │      │
        └────────┴────────┘      └─────┴──────┘
                 │                    │
                 └─────────┬──────────┘
                           ▼
                    Evidence Engine
```

---

# 142. Final End-to-End Flow

The final implementation must support:

```bash
trace scan ./labs/vending-api \
  --target http://127.0.0.1:18080
```

Internally:

```text
1. Load configuration
2. Validate scope
3. Scan repository
4. Parse source
5. Discover routes
6. Extract auth
7. Extract parameters
8. Extract call paths
9. Extract DB/external sinks
10. Build APM
11. Persist APM
12. Generate security signals
13. Rank endpoints
14. Build security slices
15. Call local AI for test planning
16. Validate AI action
17. Execute test
18. Capture observation
19. Compare baseline/test
20. Decide next action
21. Stop/repeat
22. Correlate static + runtime evidence
23. Generate finding
24. Store finding
25. Print report
```

---

# 143. Hackathon Implementation Schedule

## Day 1

### Block A

```text
project bootstrap
CLI
config
SQLite
doctor
```

### Block B

```text
Tree-sitter
file ingestion
source locations
```

### Block C

```text
FastAPI routes
Express routes
Flask routes
```

### Block D

```text
APM
NetworkX
SQLite persistence
```

---

# 144. Day 2

### Block A

```text
security signals
priority ranking
security slicing
```

### Block B

```text
scope guard
HTTPX runtime
baseline
comparison
```

### Block C

```text
authentication
BOLA
BFLA
```

### Block D

```text
SSRF
mass assignment
injection indicators
```

---

# 145. Day 3

### Block A

```text
Ollama
planner
structured actions
```

### Block B

```text
evidence correlation
findings
reports
replay
```

### Block C

```text
vending lab
callback service
Docker Compose
```

### Block D

```text
crAPI
Juice Shop
```

---

# 146. Final Hackathon Polish

Add:

```text
rich terminal output
progress bars
colors
finding grouping
source code excerpts
graph path rendering
benchmark table
JSON export
HTML report
```

Do not build:

```text
web dashboard
VS Code extension
hosted backend
cloud database
multi-agent swarm
```

until the core scan works.

---

# 147. Judge Demo

## Terminal 1

```bash
docker compose -f labs/docker-compose.yml up --build -d
```

## Terminal 2

```bash
trace scan ./labs/vending-api \
  --target http://127.0.0.1:18080
```

## Terminal 3

Optional passive ZAP:

```bash
docker run --rm \
  --network secgraph-lab \
  -v "$PWD/artifacts:/zap/wrk/:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://vuln-api:8000 \
  -r zap-baseline.html
```

Then show:

```bash
trace findings
```

and:

```bash
trace explain SG-001
```

Finally:

```bash
trace replay SG-001
```

The judge should see:

```text
source
→ attack path
→ test
→ response
→ evidence
→ finding
```

in under a few minutes.

---

# 148. Demo Story

Use the vending machine example:

```text
"Suppose an attacker can request:

GET /api/orders/{id}

The endpoint has JWT authentication.

But authentication is not authorization.

TRACE follows the ID through the application,
finds the database lookup, fails to find an
ownership constraint, and creates a controlled
cross-identity test.

The runtime response confirms the object is returned.

TRACE then links the runtime evidence back to the
exact source path."
```

That is the product story.

---

# 149. What Not To Claim

Do not claim:

```text
"finds every vulnerability"
"replaces pentesters"
"fully autonomous hacker"
"100% accurate"
"zero false positives"
"analyzes only 10% of the code"
"uses AI to understand the entire application"
```

Use:

```text
"prioritizes"
"correlates"
"validates"
"evidence-backed"
"local-first"
"extensible"
"attack-path aware"
```

---

# 150. Final Product Architecture

```text
                              TRACE
             Threat Reconnaissance & Attack-path
                    Correlation Engine
                                      │
                                      ▼
                           ┌──────────────────┐
                           │ Repository       │
                           └────────┬─────────┘
                                    ▼
                           ┌──────────────────┐
                           │ Source Indexer   │
                           │ Tree-sitter      │
                           │ ast-grep         │
                           └────────┬─────────┘
                                    ▼
                           ┌──────────────────┐
                           │ Endpoint Layer   │
                           │ Express          │
                           │ FastAPI          │
                           │ Flask            │
                           └────────┬─────────┘
                                    ▼
                           ┌──────────────────┐
                           │ ATTACK-PATH      │
                           │ MODEL            │
                           │ NetworkX+SQLite  │
                           └────────┬─────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
          ┌──────────────────┐             ┌──────────────────┐
          │ Security Signals │             │ Local AI Planner │
          └────────┬─────────┘             │ Ollama/llama.cpp │
                   │                       └────────┬─────────┘
                   └───────────────────┬────────────┘
                                       ▼
                            ┌───────────────────┐
                            │  TEST-PACK ENGINE │
                            └─────────┬─────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                ▼                     ▼                     ▼
            HTTPX tests          Schemathesis          Tool adapters
                                                        ZAP/Nuclei/etc.
                                      │
                                      ▼
                            ┌───────────────────┐
                            │ Scope Guard       │
                            └─────────┬─────────┘
                                      ▼
                            ┌───────────────────┐
                            │ Runtime Evidence  │
                            └─────────┬─────────┘
                                      ▼
                            ┌───────────────────┐
                            │ Evidence          │
                            │ Correlator        │
                            └─────────┬─────────┘
                                      ▼
                            ┌───────────────────┐
                            │ Finding Store     │
                            └─────────┬─────────┘
                                      ▼
                            ┌───────────────────┐
                            │ Terminal / JSON / │
                            │ HTML / Markdown   │
                            └───────────────────┘
```

---

# 151. Definition of Done

TRACE v0.1 is complete when:

```text
[ ] trace --help works
[ ] trace doctor works
[ ] repository indexing works
[ ] Tree-sitter parser works
[ ] source line locations are preserved
[ ] FastAPI endpoint discovery works
[ ] Express endpoint discovery works
[ ] Flask endpoint discovery works
[ ] APM is persisted in SQLite
[ ] NetworkX traversal works
[ ] security slices work
[ ] security signals work
[ ] scope guard blocks public hosts
[ ] redirect scope is enforced
[ ] HTTPX runtime works
[ ] authentication test works
[ ] BOLA test works
[ ] BFLA test works
[ ] SSRF lab test works
[ ] mass-assignment test works
[ ] injection indicator works
[ ] Ollama works locally
[ ] LLM actions are Pydantic validated
[ ] LLM cannot execute arbitrary shell
[ ] findings contain source + runtime evidence
[ ] replay works
[ ] JSON report works
[ ] HTML report works
[ ] vending lab works
[ ] callback service works
[ ] crAPI scan works
[ ] Juice Shop scan works
[ ] ZAP adapter works
[ ] Nuclei adapter works
[ ] optional tool failures do not crash TRACE
[ ] benchmark works
[ ] tests pass
[ ] no fabricated metrics in presentation
```

---

# 152. Official / Open-Source Repositories

## TRACE core

### Tree-sitter
https://github.com/tree-sitter/tree-sitter

### py-tree-sitter
https://github.com/tree-sitter/py-tree-sitter

### JavaScript grammar
https://github.com/tree-sitter/tree-sitter-javascript

### TypeScript grammar
https://github.com/tree-sitter/tree-sitter-typescript

### Python grammar
https://github.com/tree-sitter/tree-sitter-python

### ast-grep
https://github.com/ast-grep/ast-grep

### NetworkX
https://github.com/networkx/networkx

### HTTPX
https://github.com/encode/httpx

---

# 153. API Testing

### Schemathesis
https://github.com/schemathesis/schemathesis

---

# 154. Local AI

### Ollama
https://github.com/ollama/ollama

### llama.cpp
https://github.com/ggml-org/llama.cpp

---

# 155. Security Tools

### OWASP ZAP
https://github.com/zaproxy/zaproxy

### Nuclei
https://github.com/projectdiscovery/nuclei

### TruffleHog
https://github.com/trufflesecurity/trufflehog

### Nmap
https://github.com/nmap/nmap

### ffuf
https://github.com/ffuf/ffuf

### sqlmap
https://github.com/sqlmapproject/sqlmap

### Nikto
https://github.com/sullo/nikto

### Joern
https://github.com/joernio/joern

---

# 156. Vulnerable / Training Targets

### OWASP crAPI
https://github.com/OWASP/crAPI

### OWASP Juice Shop
https://github.com/juice-shop/juice-shop

---

# 157. Developer Tooling

### uv
https://github.com/astral-sh/uv

### Ruff
https://github.com/astral-sh/ruff

---

# 158. First-Day Command Checklist

## System

```bash
git --version
docker --version
docker compose version
uv --version
```

## TRACE

```bash
mkdir trace
cd trace

git init -b main

uv python install 3.12
uv venv
```

Activate:

```bash
source .venv/bin/activate
```

Then:

```bash
uv init

uv add \
  typer \
  rich \
  pydantic \
  pydantic-settings \
  networkx \
  httpx \
  orjson \
  tomli-w \
  tree-sitter-language-pack

uv add --dev \
  pytest \
  pytest-asyncio \
  ruff \
  mypy
```

Optional:

```bash
uv add schemathesis
```

---

# 159. Install Structural Search

```bash
uv tool install ast-grep-cli
```

Verify:

```bash
ast-grep --version
```

---

# 160. Local AI

Install Ollama from:

```text
https://ollama.com/download
```

Verify:

```bash
ollama --version
curl http://localhost:11434/api/tags
```

Pull the chosen local coding model:

```bash
ollama pull <chosen-model>
```

Do not hard-code model assumptions.

---

# 161. Start Local Lab

```bash
docker network create --internal secgraph-lab
```

Then:

```bash
docker compose -f labs/docker-compose.yml up --build -d
```

Check:

```bash
curl http://127.0.0.1:18080/health
```

Run TRACE:

```bash
trace scan ./labs/vending-api \
  --target http://127.0.0.1:18080
```

---

# 162. Development Order in One View

```text
BOOTSTRAP
   ↓
CLI
   ↓
REPOSITORY INGESTION
   ↓
TREE-SITTER
   ↓
FRAMEWORK ADAPTERS
   ↓
ATTACK-PATH MODEL
   ↓
SECURITY SIGNALS
   ↓
SCOPE GUARD
   ↓
HTTPX
   ↓
TEST-PACKS
   ↓
OLLAMA
   ↓
EVIDENCE CORRELATION
   ↓
REPORTING
   ↓
ZAP / NUCLEI / SCHEMATHESIS
   ↓
KALI TOOL ADAPTERS
   ↓
BENCHMARKS
   ↓
PLUGIN ECOSYSTEM
```

---

# 163. The Core Demo Loop

Do not lose sight of this:

```text
ONE ENDPOINT
     ↓
ONE ATTACK PATH
     ↓
ONE SECURITY HYPOTHESIS
     ↓
ONE SAFE CONTROLLED TEST
     ↓
ONE OBSERVATION
     ↓
ONE CORRELATION
     ↓
ONE EVIDENCE-BACKED FINDING
```

Then repeat across the application.

That loop is the core technology.

---

# 164. Final Positioning

The final one-line pitch:

> **TRACE is a local-first security intelligence engine that reconstructs an application's attack paths from source code to runtime behavior, then uses deterministic analysis and local AI to select controlled tests and produce evidence-backed findings.**

Short version for the terminal/project README:

```text
TRACE
Source → Attack Path → Test → Evidence
```

That should be the central identity of the project.
