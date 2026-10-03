---
trigger: always_on
description: Mandatory security remediation rules for autonomous coding agents.
---

# TRACE Autonomous Security Remediation Guidelines

When an AI coding agent is tasked with fixing vulnerabilities reported by TRACE or running a TRACE-Bench task, the following standards are strictly mandatory:

## 1. Zero-Dummy-Bypass Rule
- **FORBIDDEN**: Never resolve a vulnerability by hardcoding boolean flags (`if (true) return 200`), returning mock empty responses, commenting out security filters, or bypassing authentication handlers.
- **MANDATORY**: Fixes must genuinely enforce the intended business and security invariants in code (e.g. comparing session tenant identity against record tenant identity).

## 2. Broken Object-Level Authorization (BOLA / IDOR)
- When fetching, updating, or deleting any domain entity (`Record`, `User`, `Order`, `Document`) by identifier:
  1. Extract the authenticated user's ID and tenant/organization identifier from the verified security context (`Authentication`, `SecurityContextHolder`, or JWT claims).
  2. Scope the database query or in-memory retrieval to the authenticated tenant (e.g. `findByRecordIdAndTenantId(...)`).
  3. If the resource does not belong to the caller, return HTTP `403 Forbidden` or `404 Not Found`.

## 3. Broken Function-Level Authorization (BFLA)
- Privileged endpoints (e.g. administrative exports, role elevation, tenant configuration, metric resets) must explicitly verify user roles:
  1. Enforce RBAC checks (e.g. `@PreAuthorize("hasRole('ADMIN')")`, `authContext.requireRole("admin")`).
  2. Deny requests with HTTP `403 Forbidden` for standard or unprivileged users.

## 4. Server-Side Request Forgery (SSRF)
- When accepting external URLs or callbacks (`callbackUrl`, `webhookUrl`, `targetUri`):
  1. Validate the URL scheme is strictly `https` (or `http` for allowed domains).
  2. Reject all loopback, link-local, and private RFC-1918 addresses (`127.0.0.1`, `localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`).
  3. Resolve DNS names and check resolved IP addresses against private subnet blocklists before dispatching outbound HTTP calls.

## 5. Broken Authentication & Session Management
- Never expose unauthenticated endpoints that execute state-changing actions.
- Ensure all API endpoints under `/api/**` or `/admin/**` participate in the authentication barrier unless explicitly marked public.

## 6. Mass Assignment & Parameter Injection
- Do not bind untrusted HTTP request bodies directly into persistent domain entities or ORM models.
- Use explicit DTOs (Data Transfer Objects) with allowlisted fields.

## 7. Verification Requirement
- After applying any code change, execute the TRACE verification oracle (`trace_verify` or `trace verify <finding_id>`) to prove that the exploit vector is blocked and no regressions were introduced.
