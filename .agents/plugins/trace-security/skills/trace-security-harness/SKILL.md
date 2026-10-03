---
name: trace-security-harness
description: >-
  Standardized runbook and tool guide for autonomous coding agents operating with the TRACE
  Agent Harness Plugin. Guides agents through finding discovery, Attack-Path Model inspection,
  safe surgical remediation, and live verification.
---

# TRACE Security Agent Harness Runbook

The TRACE Agent Harness Plugin equips you with tools to autonomously audit codebases, investigate correlated vulnerability findings, inspect Attack-Path Models (APM), apply surgical security fixes, and verify solutions against live exploit tests.

---

## Autonomous Workflow for Security Remediation

Follow these 5 distinct phases when resolving security vulnerabilities:

```
[Phase 1: Ingest] ➔ [Phase 2: Diagnose] ➔ [Phase 3: Plan Fix] ➔ [Phase 4: Patch] ➔ [Phase 5: Verify]
```

### Phase 1: Finding & Task Ingestion
Query the TRACE findings store or benchmark task queue to identify active vulnerabilities:

1. **List all findings:**
   - MCP Tool: `trace_findings`
   - CLI: `trace findings`
2. **Inspect a specific benchmark task:**
   - MCP Tool: `trace_harness_task` with `task_id` or `finding_id`
   - CLI: `trace plugin task <task_id>`

Each finding has:
- `id`: Unique identifier (e.g. `TR-BOLA-001`, `TR-SSRF-003`)
- `category`: OWASP API Security category (e.g. BOLA, BFLA, SSRF)
- `severity`: CRITICAL, HIGH, MEDIUM, LOW
- `endpoint`: The affected HTTP endpoint
- `source_location`: File path and line numbers

---

### Phase 2: Root-Cause & Attack-Path Diagnosis
Never guess the fix. Examine the complete correlation evidence and Attack-Path Model (APM) hops:

1. **Retrieve explanation and reproduction steps:**
   - MCP Tool: `trace_explain` with `finding_id: "TR-BOLA-001"`
   - CLI: `trace explain TR-BOLA-001`
2. **Inspect the APM graph hops:**
   - MCP Tool: `trace_attack_path` with `endpoint: "/api/records/{id}"`
   
Key items to inspect in the explanation:
- `attack_path`: Sequence of hops from public HTTP entrypoint to vulnerable sink.
- `static_evidence`: Code AST patterns that triggered the hypothesis.
- `runtime_evidence`: Concrete HTTP request/response proofs demonstrating unauthorized access.
- `remediation`: Architectural guidance on how the endpoint should be secured.

---

### Phase 3: Surgical Patch Planning
Formulate a patch that enforces the invariant without modifying unrelated behavior:

#### BOLA (Broken Object-Level Authorization)
- **Problem**: Entity retrieved by ID without checking if caller owns the entity or belongs to the same tenant.
- **Fix**:
  ```kotlin
  // BEFORE (Vulnerable)
  val record = recordRepository.findById(id)
  return ResponseEntity.ok(record)

  // AFTER (Secure)
  val currentUser = SecurityContext.getCurrentUser()
  val record = recordRepository.findByIdAndTenantId(id, currentUser.tenantId)
      ?: return ResponseEntity.status(403).body("Access denied")
  return ResponseEntity.ok(record)
  ```

#### BFLA (Broken Function-Level Authorization)
- **Problem**: Privileged/administrative endpoint accessible by regular authenticated users.
- **Fix**:
  ```kotlin
  // Ensure role enforcement is present
  val user = SecurityContext.getCurrentUser()
  if (!user.roles.contains("ADMIN")) {
      return ResponseEntity.status(403).body("Administrator role required")
  }
  ```

#### SSRF (Server-Side Request Forgery)
- **Problem**: Unvalidated user-supplied URL dispatched to internal network or cloud metadata.
- **Fix**:
  ```kotlin
  // Validate destination before dispatch
  val uri = URI(callbackUrl)
  val host = uri.host.lowercase()
  if (host == "localhost" || host == "127.0.0.1" || host.startsWith("169.254.") || host.startsWith("10.") || host.startsWith("192.168.")) {
      return ResponseEntity.status(403).body("Outbound request to internal IP blocked")
  }
  ```

---

### Phase 4: Patch Application
Apply the modification using standard file editing tools (`replace_file_content` or `write_to_file`).
- Ensure no syntax or compilation errors.
- Keep modifications minimal and idiomatic.

---

### Phase 5: Deterministic Verification
Verify that the exploit vector is blocked and the endpoint remains healthy:

1. **Verify with TRACE Verification Oracle:**
   - MCP Tool: `trace_verify` with `finding_id`
   - CLI: `trace verify <finding_id>`
2. **Evaluate Patch Quality:**
   - MCP Tool: `trace_eval_patch`
   
The verification oracle will execute the active exploit test pack against the running target. A status of `RESOLVED` with `runtime_check_passed: true` confirms the fix is sound.
