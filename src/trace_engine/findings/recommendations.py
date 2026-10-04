"""Remediation and Root Cause Explanation Engine for TRACE security findings.

Generates precise, non-vague, technical root cause analyses, step-by-step remediation actions,
and concise terminal action summaries tailored to the specific vulnerability pattern.
"""

from typing import Optional, Dict, Any, List, Tuple


def get_detailed_remediation_and_root_cause(
    title: str,
    category: str,
    endpoint: str,
    static_evidence: Optional[List[str]] = None,
    filepath: str = "",
) -> Tuple[str, str, str]:
    """Generates: (root_cause_explanation, detailed_remediation_steps, short_action_summary).

    All three outputs are tailored specifically to the exact finding rather than generic category templates.
    """
    t_lower = title.lower()
    ep_lower = endpoint.lower()
    ev_text = " ".join(static_evidence or []).lower()
    cat_upper = category.upper()

    # 1. Caller-Controlled Ownership Bypass via Optional Parameter
    if "caller-controlled" in t_lower or "assert_coach_owns_athlete" in ev_text or ("coach_id" in ev_text and "bypass" in t_lower):
        root_cause = (
            f"The multi-tenant authorization assertion on `{endpoint}` is conditionally guarded by a client-supplied "
            f"query parameter (e.g. `coach_id`). Because the parameter is optional (`Optional[int] = Query(None)`), "
            f"an attacker can simply omit `?coach_id=` from the request URL to completely skip the ownership assertion "
            f"and access or modify private domain records belonging to any athlete."
        )
        remediation = (
            "1. Remove `coach_id` from client-supplied query parameters.\n"
            "2. Extract the authenticated caller's identity directly from verified session state or JWT claims "
            "(e.g., `current_user = Depends(get_current_user)`).\n"
            "3. Enforce the tenant/coach ownership check unconditionally using the session ID: "
            "`assert_coach_owns_athlete(current_user.id, user_id)` before querying or mutating the database.\n"
            "4. Return HTTP 403 Forbidden or 404 Not Found if the relationship check fails."
        )
        short_action = "Enforce caller tenant validation from session token; do not accept optional coach_id."
        return root_cause, remediation, short_action

    # 2. Public StaticFiles Directory Mount
    if "staticfiles" in t_lower or "staticfiles" in ev_text or "/session_videos" in ep_lower:
        root_cause = (
            f"The directory containing stored files is mounted publicly via FastAPI's `StaticFiles` at `{endpoint}` "
            f"without authentication or tenant authorization middleware. This completely circumvents API-level access "
            f"controls, allowing unauthenticated callers to enumerate, stream, and download private user recordings and "
            f"uploaded files directly via static HTTP GET requests."
        )
        remediation = (
            f"1. Remove the public directory mount `app.mount('{endpoint}', StaticFiles(...))`.\n"
            "2. Implement a protected API endpoint (e.g. `GET /api/media/{file_id}`) that validates caller authentication "
            "and verifies that the requested media belongs to the requesting user before streaming.\n"
            "3. Stream files securely using `FileResponse` or `StreamingResponse` after authorization.\n"
            "4. Alternatively, store sensitive files in an S3/GCS bucket and generate short-lived, pre-signed URLs."
        )
        short_action = "Remove public StaticFiles mount; serve files via authenticated FileResponse."
        return root_cause, remediation, short_action

    # 3. Broken Password Hashing & Plaintext Fallback
    if "password hashing" in t_lower or "plaintext" in ev_text or "verify_password" in t_lower:
        root_cause = (
            "Password verification logic in the authentication module contains a critical plaintext equality fallback "
            "(`if hashed_password == plain_password:`) and/or relies on a single hardcoded global salt with fast, "
            "un-keyed SHA-256 instead of an adaptive work-factor algorithm. This permits unhashed credential logins "
            "and leaves stored hashes susceptible to commodity GPU rainbow table recovery."
        )
        remediation = (
            "1. Immediately delete the plaintext equality comparison `if hashed_password == plain_password:`.\n"
            "2. Migrate password hashing to an adaptive, slow work-factor algorithm such as `bcrypt` or `Argon2id` "
            "(e.g. using `passlib.context.CryptContext(schemes=['bcrypt'])`).\n"
            "3. Ensure the hashing function automatically generates and binds a unique, cryptographically random salt per user record.\n"
            "4. Re-hash legacy passwords transparently upon user login."
        )
        short_action = "Eliminate plaintext check; migrate password hashing to bcrypt/Argon2 with per-user salt."
        return root_cause, remediation, short_action

    # 4. Unauthenticated Global Session / Data Wipe with Blast Radius
    if "blast radius" in t_lower or ("reset" in ep_lower and ("wipe" in t_lower or "global" in t_lower)):
        root_cause = (
            f"Calling `{endpoint}` without request parameters defaults to iterating across all connected users "
            f"and executes bulk deletion (`shutil.rmtree` and database row deletion) across all user accounts "
            f"without requiring authentication, session scoping, or confirmation. A single unauthenticated HTTP call "
            f"destroys the entire system's session and telemetry data."
        )
        remediation = (
            f"1. Enforce authentication dependency `Depends(get_current_user)` on `{endpoint}`.\n"
            "2. Scope the deletion logic strictly to `user_id == current_user.id` so a caller can only reset their own session.\n"
            "3. If a global multi-tenant reset is required for operations, isolate it to a privileged route protected by "
            "`Depends(require_admin)` and require multi-factor or secondary token confirmation."
        )
        short_action = "Scope deletion strictly to current_user.id; restrict global wipes to require_admin."
        return root_cause, remediation, short_action

    # 5. Privilege Escalation via Unvalidated Role Assignment
    if "role assignment" in t_lower or ("role" in ev_text and "privilege" in t_lower):
        root_cause = (
            f"The user registration/creation handler on `{endpoint}` binds a client-supplied `role` string directly "
            f"into the new user record without server-side validation or administrative authorization checks. "
            f"An unauthenticated attacker can submit `role='ADMIN'` to instantly create a persistent superuser account."
        )
        remediation = (
            "1. Remove `role` and administrative privilege attributes from public user creation schemas.\n"
            "2. Restrict administrative user creation (`/api/admin/users/create`) with `Depends(require_admin)`.\n"
            "3. Enforce a strict server-side Enum allowlist (e.g. `Role.USER`, `Role.ATHLETE`) and default all new accounts "
            "to unprivileged roles regardless of client payload."
        )
        short_action = "Protect with require_admin; enforce server-side role allowlist on user creation."
        return root_cause, remediation, short_action

    # 6. Account Takeover via Unauthenticated Password Reset
    if "reset" in ep_lower and "password" in ep_lower:
        root_cause = (
            f"The password reset endpoint `{endpoint}` modifies user credentials without requiring current password "
            f"validation, an authenticated session, or an out-of-band cryptographically signed reset token. An attacker "
            f"can overwrite the password of any user account by targeting their sequential ID or username."
        )
        remediation = (
            "1. Implement an out-of-band reset flow using time-limited, single-use cryptographically random tokens "
            "delivered to the verified user email address.\n"
            "2. For self-service password changes by logged-in users, require current password verification.\n"
            "3. For administrative password resets, guard the route with `Depends(require_admin)`."
        )
        short_action = "Require verified single-use reset token or require_admin check for password resets."
        return root_cause, remediation, short_action

    # 7. Insecure CORS Configuration
    if cat_upper == "CORS" or "cors" in t_lower:
        root_cause = (
            f"`CORSMiddleware` on `{endpoint}` is configured with `allow_origins=['*']` combined with "
            f"`allow_credentials=True`. This permits arbitrary third-party websites to execute credentialed "
            f"cross-origin requests against the backend, enabling CSRF-style data exfiltration and session riding."
        )
        remediation = (
            "1. Remove wildcard `allow_origins=['*']`.\n"
            "2. Configure an explicit array of authorized frontend domains (e.g. `allow_origins=['https://app.example.com']`).\n"
            "3. Never dynamically reflect incoming `Origin` headers into `Access-Control-Allow-Origin` when credentials are enabled."
        )
        short_action = "Remove wildcard allow_origins; define explicit list of authorized frontend domains."
        return root_cause, remediation, short_action

    # 8. Unauthenticated WebSockets
    if "websocket" in t_lower or "websocket" in ev_text:
        root_cause = (
            f"The WebSocket route `{endpoint}` accepts incoming streaming connections and dispatches real-time telemetry "
            f"without authenticating the client during the handshake, allowing unauthorized eavesdropping or malicious event injection."
        )
        remediation = (
            "1. Extract and validate authentication credentials (JWT ticket or session cookie) during the WebSocket connection handshake.\n"
            "2. Reject unauthenticated handshakes before calling `await websocket.accept()` using WebSocket close code 1008 (Policy Violation).\n"
            "3. Associate the open WebSocket connection strictly with the validated user ID."
        )
        short_action = "Validate authentication token during handshake before calling websocket.accept()."
        return root_cause, remediation, short_action

    # 9. Stateless ML / Inference Resource Exhaustion
    if "scatt-analysis" in ep_lower or "inference" in t_lower or "stateless" in t_lower:
        root_cause = (
            f"The compute-intensive inference endpoint `{endpoint}` is exposed to the public internet without authentication "
            f"or request rate-limiting, allowing unauthorized callers to trigger CPU/GPU exhaustion and denial-of-wallet."
        )
        remediation = (
            "1. Add API key or session token verification to authenticate callers.\n"
            "2. Implement rate-limiting middleware (e.g. `slowapi` or Redis token bucket) to throttle request frequency per client IP.\n"
            "3. Enforce maximum payload size limits on input telemetry arrays."
        )
        short_action = "Add API key authentication and rate-limiting middleware (slowapi) to throttle inference."
        return root_cause, remediation, short_action

    # 10. Unauthenticated User Information Disclosure
    if "user information disclosure" in t_lower or ("user" in ep_lower and cat_upper == "AUTHENTICATION" and "get" in ep_lower):
        root_cause = (
            f"Read-only endpoint `{endpoint}` discloses user profile records (ID, username, role) to unauthenticated callers, "
            f"permitting automated enumeration of all registered users in the application."
        )
        remediation = (
            f"1. Protect `{endpoint}` with `Depends(get_current_user)` or require valid session authentication.\n"
            "2. If public user profiles are intended by design, redact internal database IDs, role assignments, and private metadata."
        )
        short_action = "Protect user lookup with Depends(get_current_user) to prevent user enumeration."
        return root_cause, remediation, short_action

    fp_lower = filepath.lower()
    is_node = fp_lower.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs"))

    # 11. General BOLA / IDOR
    if cat_upper == "BOLA" or "bola" in t_lower:
        root_cause = (
            f"The handler for `{endpoint}` looks up database records using a client-supplied object ID from the URL or query "
            f"without verifying that the requested record belongs to the authenticated user's tenant or organization. "
            f"An attacker can increment or replace the ID to view or modify records belonging to other tenants."
        )
        if is_node:
            remediation = (
                "1. Extract authenticated caller ID from session state (`req.user.id` or `req.user.tenantId`).\n"
                "2. Scope database queries to verify `req.user.tenantId == record.tenantId` before returning data.\n"
                "3. Return HTTP 403 Forbidden or 404 Not Found if the resource is not owned by the caller."
            )
            short_action = "Scope database query to req.user.tenantId to enforce object-level isolation."
        else:
            remediation = (
                "1. Extract authenticated caller ID from the verified session context (e.g. `current_user = Depends(get_current_user)`).\n"
                "2. Scope database queries to both the object ID and the user's tenant: "
                "`db.query(Model).filter(Model.id == obj_id, Model.tenant_id == current_user.tenant_id).first()`.\n"
                "3. Return HTTP 403 Forbidden or 404 Not Found if the resource is not owned by the caller."
            )
            short_action = "Scope database query to authenticated current_user.tenant_id to enforce isolation."
        return root_cause, remediation, short_action

    # 12. General BFLA / Admin RBAC Missing
    if cat_upper == "BFLA" or "admin" in ep_lower or "bfla" in t_lower:
        root_cause = (
            f"Privileged administrative route `{endpoint}` is accessible without verifying that the caller possesses "
            f"administrative role permissions. Any standard user or unauthenticated client can trigger administrative actions."
        )
        if is_node:
            remediation = (
                "1. Mount role-verification middleware (`requireRole('admin')`) on the route.\n"
                "2. Verify `req.user && req.user.role === 'admin'` before executing privileged operations."
            )
            short_action = "Mount requireRole('admin') middleware on privileged administrative route."
        else:
            remediation = (
                "1. Implement declarative role-based access control (RBAC) dependencies (e.g. `Security(require_role('admin'))`).\n"
                "2. Verify that `current_user.role == 'ADMIN'` on the backend before executing privileged state changes."
            )
            short_action = "Implement declarative RBAC dependency (require_admin) on privileged administrative route."
        return root_cause, remediation, short_action

    # 13. General Authentication Missing on Sensitive Route
    if cat_upper == "AUTHENTICATION":
        root_cause = (
            f"Sensitive or state-modifying endpoint `{endpoint}` does not enforce authentication. Unauthorized callers "
            f"can trigger operations or retrieve private data without providing credentials or session tokens."
        )
        if is_node:
            remediation = (
                f"1. Mount authentication middleware `verifyToken` or `router.use(authMiddleware)` on `{endpoint}`.\n"
                "2. Reject unauthenticated requests with HTTP 401 Unauthorized."
            )
            short_action = "Mount verifyToken middleware on Express route."
        else:
            remediation = (
                f"1. Mount authentication dependency `Depends(get_current_user)` or security middleware on `{endpoint}`.\n"
                "2. Reject unauthenticated requests with HTTP 401 Unauthorized."
            )
            short_action = "Protect route with Depends(get_current_user) to block unauthenticated callers."
        return root_cause, remediation, short_action

    # 14. Path Traversal
    if cat_upper == "PATH_TRAVERSAL":
        root_cause = (
            f"Endpoint `{endpoint}` accepts file or path parameters without verifying that the resolved path resides "
            f"strictly within the intended base directory. Attackers can use path traversal sequences (`..`) to access arbitrary system files."
        )
        remediation = (
            "1. Sanitize file path inputs using `os.path.basename()` or `pathlib.Path.resolve()`.\n"
            "2. Verify that `resolved_path.is_relative_to(base_dir)` before opening or reading files."
        )
        short_action = "Sanitize file input with basename() and verify resolved directory containment."
        return root_cause, remediation, short_action

    # 15. SSRF
    if cat_upper == "SSRF":
        root_cause = (
            f"Endpoint `{endpoint}` accepts a user-controlled destination URL and dispatches outbound HTTP requests without "
            f"validating the host against an allowlist, allowing attackers to probe internal cloud metadata and RFC-1918 networks."
        )
        remediation = (
            "1. Validate target URLs against a strict allowlist of authorized hostnames.\n"
            "2. Resolve DNS names and reject loopback (`127.0.0.1`, `localhost`) and private RFC-1918 IP addresses before dispatching HTTP calls."
        )
        short_action = "Enforce domain allowlist and block loopback/private RFC-1918 IPs on outbound HTTP."
        return root_cause, remediation, short_action

    # 16. SQL / NoSQL Injection
    if cat_upper == "INJECTION":
        root_cause = (
            f"Endpoint `{endpoint}` routes user-supplied query parameters to the database layer without verified parameterization, "
            f"permitting SQL syntax injection and unauthorized database manipulation."
        )
        remediation = (
            "1. Use parameterized queries, prepared statements, or ORM abstraction methods for all database operations.\n"
            "2. Never concatenate or format raw client inputs into SQL query strings."
        )
        short_action = "Use parameterized SQL queries or ORM models; never concatenate raw user input."
        return root_cause, remediation, short_action

    # Default fallback
    root_cause = f"Security vulnerability of category `{category}` identified in `{endpoint}`."
    remediation = "Apply strict authentication, tenant authorization boundaries, and input validation to this attack path."
    short_action = f"Apply strict access control and input validation on {category} attack path."
    return root_cause, remediation, short_action


def get_remediation_for_category(category: str, filepath: str = "", framework: str = "") -> str:
    """Backwards-compatible remediation accessor."""
    _, rem, _ = get_detailed_remediation_and_root_cause(
        title=category,
        category=category,
        endpoint="endpoint",
        filepath=filepath,
    )
    return rem
