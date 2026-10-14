# Patch patterns per category

Each pattern states the invariant a fix must enforce.

## BOLA (broken object-level authorization)

Scope every object lookup to the caller:

```kotlin
// BEFORE
val record = recordRepository.findById(id)
// AFTER
val user = SecurityContext.getCurrentUser()
val record = recordRepository.findByIdAndTenantId(id, user.tenantId)
    ?: return ResponseEntity.status(403).body("Access denied")
```

## BFLA (broken function-level authorization)

Gate privileged endpoints on role:

```kotlin
if (!user.roles.contains("ADMIN"))
    return ResponseEntity.status(403).body("Administrator role required")
```

## SSRF (server-side request forgery)

Validate the destination before dispatch; block loopback, link-local
(`169.254.*`), and RFC 1918 ranges.

## Injection (SQLi / command)

Parameterize queries and shell calls; never format user input into them.

## Mass assignment

Allowlist bindable fields; never bind the raw request body to a model.

## Path traversal

Resolve to absolute path and require containment in the intended directory.

## CORS

Never reflect arbitrary origins with credentials; use an explicit allowlist.
