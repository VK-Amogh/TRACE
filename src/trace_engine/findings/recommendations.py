"""Remediation recommendations for security findings."""

REMEDIATION_MAP = {
    "BOLA": (
        "Enforce strict object ownership validation before returning records. "
        "Query using both the object ID and the authenticated user/tenant ID (e.g. `WHERE id = :id AND user_id = :current_user.id`)."
    ),
    "BFLA": (
        "Implement declarative role-based access control (RBAC) middleware. "
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
}


def get_remediation_for_category(category: str) -> str:
    return REMEDIATION_MAP.get(
        category.upper(),
        "Review access control and input validation on this attack path.",
    )
