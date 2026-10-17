# Injection-class playbook

Covers `TR-INJ`, `TR-SSTI`, `TR-TRAV`, `TR-DESER`. General rule: keep
untrusted data in the *data* channel. Never build code, queries, templates,
paths, or object graphs from it by string operations, and prefer allow-lists
to blocklists.

## INJ: SQL and command injection

**Invariant:** user input is bound as a parameter, never concatenated or
interpolated into SQL or a shell command.

```python
# BEFORE: db.execute(f"SELECT * FROM items WHERE name LIKE '%{q}%'")
db.execute(text("SELECT * FROM items WHERE name LIKE :q"), {"q": f"%{q}%"})
```

```javascript
// pg
await pool.query('SELECT * FROM items WHERE name ILIKE $1', [`%${q}%`]);
```

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM items WHERE name LIKE ?");
ps.setString(1, "%" + q + "%");
```

```go
rows, err := db.QueryContext(ctx, "SELECT id FROM items WHERE name LIKE $1", "%"+q+"%")
```

- Identifiers (column, sort order, table) cannot be parameters: map the input
  to an allow-list (`{"price": "price", "name": "name"}`) and use the mapped
  constant.
- ORMs: use the query builder; `raw()`/`text()`/`$where` with interpolation is
  the same bug.
- Limit the DB account's privileges so a residual bug has a small blast radius.
- Command injection: do not use a shell. `subprocess.run([...], shell=False)`,
  `execFile` not `exec`, fixed argument vectors, validate any filename or
  option against an allow-list, and prefer a library over spawning a tool.

```python
subprocess.run(["convert", str(safe_path), str(out_path)], check=True, timeout=10)
```

Tests: payloads such as `' OR '1'='1`, `%`, and a quote in the term return
no extra rows and no 500; a legitimate search still works.

Note: TRACE's SQL rule fires on search/filter/query routes with
interpolated SQL. Grep the rest of the data layer for the same pattern
(`f"...{`, `+ var +`, `.format(`, `%s %` with SQL) after fixing.

## SSTI: server-side template injection

**Invariant:** user input is rendered as template *data*, never as template
*source*.

```python
# BEFORE: render_template_string(f"Hello {name}")  /  Template(user_text).render()
render_template("hello.html", name=name)            # fixed template, name is a variable
```

- Never pass request data to `render_template_string`, `Template(...)`,
  `eval`, or `Environment.from_string`.
- If users must author templates, use a sandboxed environment
  (`jinja2.sandbox.SandboxedEnvironment`) with a minimal context, or a
  logic-less format (Mustache), and validate templates at save time.
- Keep autoescape on.

Tests: `{{7*7}}` renders literally as `{{7*7}}`, not `49`.

## TRAV: path traversal

**Invariant:** the resolved path stays inside the intended base directory.

```python
BASE = Path("/srv/uploads").resolve()

def safe_open(name: str) -> Path:
    p = (BASE / name).resolve()
    if not p.is_relative_to(BASE):          # Python 3.9+
        raise HTTPException(status_code=400)
    return p
```

```javascript
const full = path.resolve(BASE, name);
if (!full.startsWith(BASE + path.sep)) return res.sendStatus(400);
```

```java
Path p = base.resolve(name).normalize();
if (!p.startsWith(base)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
```

- Resolve **before** the check (symlinks, `..`, encoded separators), and
  check after the final join. `startsWith` without a trailing separator
  matches sibling directories (`/srv/uploads-evil`).
- Prefer an id -> stored filename mapping over accepting names at all.
- Reject absolute paths and drive letters/UNC on Windows.
- For uploads: generate the server-side name, allow-list extensions *and*
  verify content type, store outside the web root.

Tests: `../../etc/passwd`, `..%2f..%2f`, an absolute path and a symlink
inside the base all return 400/404; a legitimate file works.

## DESER: unsafe deserialization

**Invariant:** untrusted bytes are parsed with a data-only format and a
schema, never an object-graph deserializer.

- Python: no `pickle.loads`, `yaml.load` (use `yaml.safe_load`), `marshal`
  on untrusted data. Use JSON + a Pydantic model.
- Java: avoid native `ObjectInputStream` for untrusted data; use JSON with
  explicit types; if unavoidable, set a deserialization filter allow-list.
- Node: avoid `node-serialize`-style libraries and `eval`-based parsing.
- PHP: `json_decode`, not `unserialize` on user input.
- Sign or MAC any serialized state that must round-trip through the client,
  and still parse it with a data-only format.

Tests: a crafted pickle/YAML object payload is rejected with 400, with no
side effect.
