"""Remediation recommendations for security findings."""

from typing import Optional


REMEDIATION_MAP_PYTHON = {
    "BOLA": (
        "Enforce strict object ownership validation before returning records. "
        "Query using both the object ID and the authenticated user/tenant ID (e.g. `WHERE id = :id AND user_id = :current_user.id`)."
    ),
    "BFLA": (
        "Implement declarative role-based access control (RBAC) dependencies (e.g. `Security(require_role('admin'))`). "
        "Validate user privileges on the backend for every privileged/administrative route."
    ),
    "AUTHENTICATION": (
        "Protect this route with authentication dependencies (e.g. `Depends(get_current_user)` or security middleware) "
        "to ensure unauthorized users cannot trigger state-changing or sensitive operations."
    ),
    "SSRF": (
        "Avoid making arbitrary outbound HTTP requests with user-controlled URLs. "
        "Implement a strict destination domain whitelist and block loopback/internal IP addresses (RFC 1918)."
    ),
    "INJECTION": (
        "Use parameterized queries, prepared statements, or ORM abstraction for all database operations. "
        "Never format or concatenate raw client inputs into SQL/command strings."
    ),
    "MASS_ASSIGNMENT": (
        "Define explicit request DTO schemas (e.g. Pydantic models with only allowed mutable fields). "
        "Do not allow raw dictionary binding directly into database models."
    ),
    "PATH_TRAVERSAL": (
        "Sanitize file path inputs using `os.path.basename()` or `pathlib.Path.resolve()`, "
        "and verify that the resolved path is strictly within the allowed directory. Disallow path traversal sequences (`..`)."
    ),
    "SSTI": (
        "Avoid rendering untrusted user inputs directly inside template engines. "
        "Use contextual output encoding or sandbox template evaluation environments."
    ),
    "CORS": (
        "Do not reflect arbitrary Origin headers or use wildcard `*` with credentials. "
        "Configure an explicit allowlist of trusted origins."
    ),
    "DESERIALIZATION": (
        "Avoid deserializing untrusted payloads (e.g. `pickle.loads`). "
        "Use safe serialization formats like standard JSON with strict schema validation."
    ),
}

REMEDIATION_MAP_NODE = {
    "BOLA": (
        "Enforce strict object ownership validation before returning or modifying records. "
        "Scope queries using both the object ID and the authenticated user/tenant identity (e.g. `findByIdAndUserId(req.params.id, req.user.id)` or `WHERE id = ? AND tenant_id = ?`)."
    ),
    "BFLA": (
        "Implement role-based access control (RBAC) middleware (e.g. `requireRole('admin')` or `checkPermission(...)`). "
        "Validate `req.user.role` on the backend before executing privileged operations."
    ),
    "AUTHENTICATION": (
        "Mount authentication middleware (e.g. `router.use(verifyToken)` or `app.use('/api/...', verifyToken, router)`) "
        "to ensure unauthorized users cannot trigger state-changing or sensitive operations."
    ),
    "SSRF": (
        "Avoid making outbound HTTP requests (e.g. with `axios` or `fetch`) using user-controlled URLs. "
        "Implement a strict destination domain allowlist and block loopback (`127.0.0.1`, `localhost`) and private RFC-1918 IP addresses."
    ),
    "INJECTION": (
        "Use parameterized queries, prepared statements, or ORM abstractions (e.g. Prisma, Mongoose, TypeORM, Knex). "
        "Never concatenate or interpolate raw `req.body` or `req.query` into database queries or shell commands."
    ),
    "MASS_ASSIGNMENT": (
        "Define explicit request DTO schemas (e.g. using Zod, Joi, or TypeScript DTOs) and pick allowlisted fields from `req.body`. "
        "Never pass raw `req.body` directly into database creation or update functions."
    ),
    "PATH_TRAVERSAL": (
        "Sanitize file path inputs using `path.basename()` or `path.resolve()`, "
        "and verify that the target path strictly resides within the intended root directory (e.g. `resolvedPath.startsWith(BASE_DIR)`). Disallow directory traversal sequences (`..`)."
    ),
    "SSTI": (
        "Avoid rendering untrusted user inputs directly inside template engines. "
        "Use contextual output encoding or sandbox template evaluation environments."
    ),
    "CORS": (
        "Do not reflect the `Origin` request header or allow `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. "
        "Configure an explicit allowlist of trusted origins."
    ),
    "DESERIALIZATION": (
        "Avoid deserializing untrusted payloads (e.g. `node-serialize`). "
        "Use safe data serialization formats like standard `JSON.parse` with strict schema validation."
    ),
}

REMEDIATION_MAP_GO = {
    "BOLA": (
        "Enforce strict tenant and user ownership validation. "
        "Scope database queries to the authenticated user ID from context (e.g. `db.Where(\"id = ? AND user_id = ?\", id, currentUserID)`)."
    ),
    "BFLA": (
        "Implement role-based authorization checks in Gin/Echo middleware. "
        "Verify user claims from context before proceeding with administrative actions."
    ),
    "AUTHENTICATION": (
        "Protect this route with authentication middleware (e.g. Gin/Echo middleware validating JWT/session token into context) "
        "to ensure unauthorized users cannot trigger state-changing operations."
    ),
    "SSRF": (
        "Validate target URLs against an allowlist and block private IP ranges before executing `http.Get` or `http.Post`."
    ),
    "INJECTION": (
        "Use parameterized SQL placeholders (`?` or `$1`) with `database/sql` or GORM. Never concatenate input into raw SQL queries."
    ),
    "MASS_ASSIGNMENT": (
        "Bind incoming requests to dedicated request structs with strictly permitted fields instead of raw map or model structs."
    ),
    "PATH_TRAVERSAL": (
        "Use `filepath.Clean` and `filepath.Rel` to verify file paths stay within the target base directory."
    ),
    "SSTI": "Ensure HTML templates use context-aware escaping (`html/template`).",
    "CORS": "Configure explicit origins in CORS middleware. Do not allow wildcard origins with credentials.",
    "DESERIALIZATION": "Use standard `encoding/json` with typed Go structs for decoding untrusted client data.",
}

# Default backwards-compatible map
REMEDIATION_MAP = REMEDIATION_MAP_PYTHON


def get_remediation_for_category(category: str, filepath: str = "", framework: str = "") -> str:
    """Returns framework- and language-tailored remediation recommendations."""
    cat_upper = category.upper()
    file_lower = filepath.lower()

    # Detect language / framework
    if any(file_lower.endswith(ext) for ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")) or framework.lower() in ("express", "nextjs", "react_router", "node"):
        return REMEDIATION_MAP_NODE.get(
            cat_upper,
            "Review access control, authentication middleware, and input validation on this attack path.",
        )
    elif file_lower.endswith(".go") or framework.lower() == "go":
        return REMEDIATION_MAP_GO.get(
            cat_upper,
            "Review access control and input validation on this attack path.",
        )
    elif file_lower.endswith(".py") or framework.lower() in ("fastapi", "flask", "django"):
        return REMEDIATION_MAP_PYTHON.get(
            cat_upper,
            "Review access control and input validation on this attack path.",
        )

    # Fallback to general remediation
    return REMEDIATION_MAP_NODE.get(cat_upper) or REMEDIATION_MAP_PYTHON.get(
        cat_upper,
        "Review access control and input validation on this attack path.",
    )
