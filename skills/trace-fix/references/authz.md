# Authorization and authentication playbook

Covers `TR-BOLA`, `TR-CHAIN`, `TR-BFLA`, `TR-AUTH`, `TR-MASS`.
OWASP API Security Top 10 (2023): API1 BOLA, API2 Broken Authentication,
API3 Broken Object Property Level Authorization (includes mass assignment),
API5 BFLA.

## BOLA: object access constrained by caller

**Invariant:** the identity of the caller is part of every object lookup.

Signs in the finding: a `GET/PUT/PATCH/DELETE /things/{id}` handler fetches by
id alone; a probe as user B read user A's object; `TR-CHAIN` shows a leaked id
unlocking a second route.

Fix at the data boundary so every caller inherits it:

```python
# FastAPI + SQLAlchemy: scope in the repository, 404 on foreign or missing
def get_record(db: Session, record_id: int, user: User) -> Record:
    rec = db.scalar(
        select(Record).where(Record.id == record_id, Record.tenant_id == user.tenant_id)
    )
    if rec is None:
        raise HTTPException(status_code=404)   # same response for missing and foreign
    return rec
```

```javascript
// Express + Mongoose: owner is part of the query, not a post-check
const doc = await Workspace.findOne({ _id: req.params.id, ownerId: req.user.id });
if (!doc) return res.status(404).json({ error: 'Not found' });
```

```java
// Spring Data: derive the scoped finder; never expose findById to controllers
Optional<Record> findByIdAndTenantId(Long id, Long tenantId);
```

```go
// database/sql
row := db.QueryRowContext(ctx,
  "SELECT id, body FROM records WHERE id = $1 AND tenant_id = $2", id, claims.TenantID)
```

Notes:
- Cover **all** verbs and nested routes (`/orgs/{o}/projects/{p}`): check
  the child belongs to the parent *and* the parent to the caller.
- Take identity from the verified token/session, never from a request
  parameter, header (`x-tenant-id`), or body.
- Return 404 for foreign objects when existence is itself sensitive, 403
  otherwise; be consistent.
- Random ids (UUIDs) reduce guessing; they do not replace the check.
- List endpoints need the same scoping, plus pagination limits.
- Chains: after fixing, a leaked id must be useless on the second route
  because that route is scoped too.

Tests: user B requests A's object on every verb -> 404/403 and no body
fields leak; user A still succeeds; list as B excludes A's rows.

## BFLA: privileged function needs privileged role

**Invariant:** the server decides the caller's role from verified identity
and enforces it before the action.

```python
def require_role(*roles):
    def dep(user: User = Depends(current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403)
        return user
    return dep

@router.post("/admin/users/{uid}/role", dependencies=[Depends(require_role("admin"))])
```

```javascript
router.use('/admin', verifyToken, requireRole('admin'));   // default-deny the whole prefix
```

```java
@PreAuthorize("hasRole('ADMIN')")   // plus @EnableMethodSecurity; deny by default in the filter chain
```

Notes:
- Apply to the whole admin router or prefix, not each handler.
- Role-assignment routes (create/register/update-role): ignore a client-sent
  `role`; set it server-side; only admins may change roles.
- HTTP method matters: `GET /x` guarded but `DELETE /x` open is a common gap.
- Header checks such as "Authorization contains admin" are not authorization.

Tests: normal-user token on every admin route and method -> 403; admin -> 2xx;
unauthenticated -> 401.

## AUTH: authentication gaps

**Invariant:** every non-public route authenticates before any work happens,
and secrets are stored so a database leak does not leak passwords.

- Default-deny: global middleware/dependency for authentication; mark the
  few public routes explicitly (`/health`, `/login`, `/docs` if intended).
- Expensive endpoints (LLM, report generation) also need auth **and** rate
  limiting, or they are a denial-of-wallet vector.
- Sessions: bind the session to the authenticated user and check it on each
  state change (`session.user_id == req.user.id`); unguessable ids from a
  CSPRNG.
- Passwords: use argon2id, bcrypt, or scrypt with per-password salt via a
  maintained library. Remove plaintext-comparison fallbacks and global salts.
  Compare with the library's verify (constant time). Rehash on login if
  parameters are outdated.

```python
from argon2 import PasswordHasher
ph = PasswordHasher()
ph.hash(pw)                 # store
ph.verify(stored, pw)       # raises on mismatch; never `==`
```

- Tokens: verify signature, `exp`, issuer and audience; pin the algorithm;
  reject `alg: none`.

Tests: no token -> 401 on each protected route; expired/forged token -> 401.

## MASS: mass assignment / property-level authorization

**Invariant:** only fields the caller may set are accepted, and only fields
the caller may see are returned.

```python
class UserUpdate(BaseModel):          # input schema: explicit allow-list
    display_name: str | None = None
    model_config = ConfigDict(extra="forbid")   # unknown fields rejected
```

```javascript
const { displayName, bio } = req.body;      // pick, never spread req.body into the model
await User.updateOne({ _id: req.user.id }, { displayName, bio });
```

Django: `ModelSerializer.Meta.fields` as an explicit list (never
`__all__` for write serializers) with `read_only_fields`.
Rails: `params.require(:user).permit(:display_name)`.

Notes: separate input and output schemas; admin-only fields get a separate
admin schema; never let clients set `role`, `is_admin`, `tenant_id`,
`owner_id`, `balance`, or `verified`.

Tests: send `{"role": "admin"}` as a normal user -> 400/422 or ignored, and
the stored value unchanged.
