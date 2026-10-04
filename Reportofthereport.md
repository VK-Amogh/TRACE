# Verification Report — `TRACE_SECURITY_REPORT.md`

**Subject:** Fact-check of all 44 findings in `TRACE_SECURITY_REPORT.md`
**Method:** Manual line-by-line audit of `backend/main.py` (1482 lines), `backend/models.py`, frontend auth surface, and dependency scanning.
**Result:** 36 true, 2 partially true, 6 false positives.

---

## 1. Scorecard

| Verdict | Count | % |
|---|---|---|
| **True** | 36 | 82% |
| **Partially true** (correct issue, incorrect reasoning) | 2 | 4% |
| **False positive** | 6 | 14% |
| **Total** | 44 | 100% |

Every source line reference in the original report matches the current file, so the
report was generated against this exact commit and its line numbers are trustworthy.

The problem is not accuracy of location — it is **severity inflation**. 44 "correlated
findings" reduce to roughly **9 distinct real issues**.

---

## 2. Root Cause

All 36 confirmed findings stem from a single omission: **the application has no
authentication layer.**

```
backend/main.py:47   def verify_password(...)      ← the only auth code in the repository
backend/main.py:463  ...used exclusively inside /api/auth/login
```

Confirmed absent across the whole backend:

- No `get_current_user` / `require_admin` dependency
- No `HTTPBearer`, `OAuth2`, or API-key scheme
- No authentication middleware
- No `Authorization` header handling
- No JWT issuance or validation

A repository-wide grep for `Depends(get_current_user)`, `HTTPBearer`, `OAuth2`,
`Authorization`, and `require_admin` returns **zero** functional hits. All 31 routes are
open to unauthenticated callers.

### 2.1 There is no identity layer to protect endpoints with

This is the critical structural point. `POST /api/auth/login` (`main.py:457-470`) returns
**no token**:

```python
return {"status": "success", "id": user.id, "username": user.username,
        "role": user.role, "coach_id": user.coach_id}
```

The frontend confirms the absence: a search for `token`, `jwt`, `Authorization`,
`localStorage`, and `sessionStorage` across `frontend/src/**` returns only two hits, both
unrelated to auth (`AthleteView.tsx:41,60` — a `athlete_view_mode` UI preference).

Consequence: role selection is pure client-side routing. Any user can open the Coach or
Admin view by editing local state. **Adding `Depends(get_current_user)` is therefore not a
drop-in fix** — there is no session infrastructure to build the dependency on top of.
A token/session mechanism must be introduced first.

---

## 3. Finding-by-Finding Mapping

### 3.1 AUTHENTICATION — 25 findings, all TRUE

Every claim ("No auth middleware or dependency detected") is accurate.

| ID | Endpoint | Line | Assessment |
|---|---|---|---|
| TR-AUTH-002 | `GET /api/user/{user_id}` | 472 | True — low impact; returns only id/username/role, **no password hash leaked** |
| TR-AUTH-004 | `GET /api/admin/users` | 490 | True — discloses full user roster (id, username, role, coach_id) |
| TR-AUTH-006 | `POST /api/admin/users/create` | 503 | True — and `role` is unvalidated (see 3.4) |
| TR-AUTH-010 | `PUT /api/admin/users/{user_id}/assign-coach` | 533 | True |
| TR-AUTH-014 | `PUT /api/admin/users/{user_id}/reset-password` | 547 | True — **enables full account takeover** |
| TR-AUTH-018 | `DELETE /api/admin/users/{user_id}` | 556 | True — unauthenticated user deletion |
| TR-AUTH-019 | `POST /api/coach/settings` | 565 | True — state-changing |
| TR-AUTH-020 | `GET /api/coach/settings` | 579 | True |
| TR-AUTH-021 | `POST /api/session/reset` | 590 | True — **destructive global action** (see 4.4) |
| TR-AUTH-023 | `POST /api/shot` | 725 | True |
| TR-AUTH-024 | `POST /api/demo-shot` | 805 | True |
| TR-AUTH-026 | `GET /api/story/{user_id}/{date}` | 933 | True |
| TR-AUTH-027 | `GET /api/session/active` | 1007 | True |
| TR-AUTH-028 | `GET /api/session/{session_id}/shots` | 1032 | True |
| TR-AUTH-029 | `GET /api/coach/{coach_id}/active` | 1062 | True |
| TR-AUTH-030 | `GET /api/coach/{coach_id}/athletes` | 1096 | True |
| TR-AUTH-031 | `POST /api/session/start` | 1122 | True |
| TR-AUTH-033 | `POST /api/session/end` | 1134 | True |
| TR-AUTH-035 | `POST /api/video/upload/{session_id}/{shot_id}` | 1180 | True |
| TR-AUTH-038 | `GET /api/video/play/{session_id}/{shot_id}` | 1193 | True |
| TR-AUTH-040 | `GET /api/athlete/{user_id}/history` | 1213 | True |
| TR-AUTH-041 | `GET /api/session/latest/story` | 1286 | True |
| TR-AUTH-042 | `GET /api/session/{session_id}/story` | 1309 | True |
| TR-AUTH-043 | `GET /api/coach/{coach_id}/history` | 1322 | True |
| TR-AUTH-044 | `POST /api/scatt-analysis` | 1473 | True — low impact; stateless inference, no data returned |

### 3.2 BFLA — 5 findings, all TRUE but duplicative

BFLA and AUTH findings describe the **same missing check**. They are not independent
issues and should not be counted separately in a risk total.

| ID | Endpoint | Line |
|---|---|---|
| TR-BFLA-003 | `GET /api/admin/users` | 490 |
| TR-BFLA-005 | `POST /api/admin/users/create` | 503 |
| TR-BFLA-009 | `PUT .../assign-coach` | 533 |
| TR-BFLA-013 | `PUT .../reset-password` | 547 |
| TR-BFLA-017 | `DELETE /api/admin/users/{user_id}` | 556 |

### 3.3 BOLA — 6 findings, all TRUE

Object-level authorization is absent. All object IDs are sequential integers and
enumerable.

| ID | Endpoint | Line | Consequence |
|---|---|---|---|
| TR-BOLA-001 | `GET /api/user/{user_id}` | 472 | Enumerate all users |
| TR-BOLA-008 | `PUT .../assign-coach` | 533 | Reassign any athlete to any coach |
| TR-BOLA-012 | `PUT .../reset-password` | 547 | Reset any account's password |
| TR-BOLA-016 | `DELETE /api/admin/users/{user_id}` | 556 | Delete any user |
| TR-BOLA-025 | `GET /api/story/{user_id}/{date}` | 933 | Read any athlete's AI match story |
| TR-BOLA-039 | `GET /api/athlete/{user_id}/history` | 1213 | Read any athlete's full session history |

### 3.4 MASS_ASSIGNMENT — 1 partial, 2 false positives

The category is misapplied in all three cases, but one finding points at a real bug
under the wrong label.

**`TR-MASS-007` — `POST /api/admin/users/create` (PARTIALLY TRUE)**

Not mass assignment. The request schema is explicit and the handler constructs the ORM
object field-by-field:

```python
class CreateUserRequest(BaseModel):        # main.py:483-488
    name: str; email: str; password: str
    role: str; coach_id: Optional[int] = None

new_user = models.User(                    # main.py:519-524
    username=clean_email,
    hashed_password=hash_password(req.password),
    role=req.role.upper(),                 # ← attacker-controlled, unvalidated
    coach_id=coach_id
)
```

**However**, `role` is accepted verbatim with no allow-list check. Combined with
`TR-AUTH-006` (no auth on the endpoint), an unauthenticated attacker can create a user
with `role="ADMIN"` and then log in with full admin privileges. This is a genuine
**privilege-escalation via unvalidated input** finding — the report's category is wrong,
but the risk is real and arguably more severe than "mass assignment".

**`TR-MASS-011` — `PUT .../assign-coach` (FALSE POSITIVE)**

```python
class AssignCoachRequest(BaseModel):       # main.py:530-531
    coach_id: Optional[int] = None
```

Single explicitly declared field. Nothing to mass-assign.

**`TR-MASS-015` — `PUT .../reset-password` (FALSE POSITIVE)**

```python
class ResetPasswordRequest(BaseModel):     # main.py:544-545
    new_password: str
```

Single explicitly declared field. Nothing to mass-assign.

### 3.5 DESERIALIZATION — 4 findings, ALL FALSE POSITIVES

**`TR-DESER-022`, `TR-DESER-032`, `TR-DESER-034`, `TR-DESER-037`**

All four share the identical non-evidence:

> "State restoration path pattern in method POST: /api/session/..."

This is a regex matching the substring `session` near a `POST` route. It is not an
analysis of data flow.

Verification: every one of these handlers deserializes a typed Pydantic model, never
untrusted serialized objects.

- `/api/session/reset` → `Optional[SessionResetRequest]`
- `/api/session/start` → `SessionStartRequest(user_id: int)`
- `/api/session/end` → `SessionEndRequest`
- `/api/video/upload` → reads `UploadFile` bytes and writes them to disk verbatim

The only `pickle` calls in the repository are in **offline training scripts**, unreachable
from any HTTP route:

- `backend/src/scatt_production_v3_1.py:435` — `pickle.load(f)`
- `scatt_production_v3_2.py:406` — `pickle.load(f)`

These are legitimate model-persistence calls that load artifacts the developer trained
locally. They are not attacker-reachable. (Note: loading pickled artifacts *is* a
supply-chain consideration if those `.pkl` files are ever replaced by an untrusted party,
but that is a different threat model from the one claimed here.)

### 3.6 PATH_TRAVERSAL — 1 finding, PARTIALLY TRUE

**`TR-TRAV-036` — `POST /api/video/upload/{session_id}/{shot_id}` (PARTIALLY TRUE)**

The cited evidence is:

> "File/path parameter names detected: `['file']`"

That is the `UploadFile` parameter. The `UploadFile` object is not attacker-controlled in
any traversal-relevant way; the filename used on disk comes from `shot_id`, not from
`file`. The evidence points at the wrong variable.

The real risk is in `shot_id`, which is sanitized only for colons and spaces:

```python
# main.py:1180-1186
async def upload_video_clip(session_id: int, shot_id: str, file: UploadFile = File(...)):
    session_folder = VIDEO_TEMP_ROOT / str(session_id)
    session_folder.mkdir(exist_ok=True)
    safe_shot_id = shot_id.replace(":", "-").replace(" ", "_")   # ← no / or .. handling
    dest = session_folder / f"{safe_shot_id}.webm"
```

Analysis:
- `session_id` is typed `int`, so it is **safe** — cannot carry traversal.
- `shot_id` is typed `str`. FastAPI's default `str` path converter will not match a
  literal `/`, but a percent-encoded `%2F` is matched against the raw path and then
  decoded by Starlette, so `..%2F..%2F..%2Ftmp%2Fevil` plausibly becomes
  `session_folder / "../../../tmp/evil.webm"`.
- No `pathlib.resolve()` containment check and no basename validation are applied.

Verdict: correct endpoint, wrong evidence, real but **unconfirmed exploitability**. This
should be reported as "insufficient filename sanitization" at MEDIUM, not "path traversal"
at HIGH.

---

## 4. Issues the Report Missed

These are more severe than several findings that were reported, and none appear in the
original document.

### 4.1 The authorization helper is opt-in and caller-controlled — HIGH

`assert_coach_owns_athlete()` (`main.py:280-287`) is invoked only when the caller supplies
a `coach_id` query parameter. That parameter is **optional and entirely attacker-supplied**:

```python
def get_match_story(user_id: int, date: str, coach_id: Optional[int] = None, ...)
    if coach_id is not None:
        assert_coach_owns_athlete(db, coach_id, user_id)   # skipped when omitted
```

Affected endpoints: `main.py:933`, `1033`, `1194`, `1214`, `1287`, `1310`.

**Simply omitting `?coach_id=` from the URL bypasses every ownership check.** The
multi-athlete segregation described in the README is therefore not enforced at the API
boundary — it is enforced only by a well-behaved frontend. This is worse than the BOLA
findings that were reported, because it means the access-control code that appears to
exist provides no actual protection.

### 4.2 Session videos are served publicly via StaticFiles — HIGH

```python
# main.py:205
app.mount("/session_videos", StaticFiles(directory="session_videos"), name="session_videos")
```

This mounts the video directory with **no authentication whatsoever**, fully bypassing
the ownership check on `GET /api/video/play/{session_id}/{shot_id}`. Any athlete's shot
replay clips are retrievable by direct URL. The `coach_id` check on the API endpoint is
therefore moot for confidentiality.

### 4.3 Password hashing is broken — HIGH

```python
# main.py:42-51
def hash_password(password: str) -> str:
    salt = "snyptr_secure_salt_2026"
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    if hashed_password == plain_password:      # ← plaintext acceptance
        return True
    return hash_password(plain_password) == hashed_password
```

Three distinct defects:

1. **Plaintext fallback.** Any user row whose `hashed_password` equals the submitted
   plaintext is accepted. This silently permits login with a legacy plaintext credential.
2. **Single hardcoded global salt.** Every user shares the same salt, so all hashes are
   susceptible to a single precomputed rainbow table. A salt must be per-user and random.
3. **Unsuitable algorithm.** Fast SHA-256 without a work factor (bcrypt/scrypt/argon2) is
   trivially brute-forced on commodity GPUs.

### 4.4 Unauthenticated global session wipe — HIGH

```python
# main.py:591-593
async def reset_session(req: Optional[SessionResetRequest] = None, ...):
    user_ids = [req.user_id] if (req and req.user_id) else list(user_sessions.keys())
```

Calling `POST /api/session/reset` with an empty body iterates **every** connected athlete,
deletes their `ShotRecord`, `SessionSummary`, and `Session` rows, and `shutil.rmtree`s
their video folders. One unauthenticated HTTP request destroys all session data for all
users. The report flags the endpoint as unauthenticated (TR-AUTH-021) but does not identify
the blast radius.

### 4.5 CORS allows all origins with credentials — MEDIUM

```python
# main.py:208-214
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

`allow_origins=["*"]` combined with `allow_credentials=True` is a dangerous pairing;
browsers reject the credentialed combination, but the intent signals zero origin
restriction. Combined with the absence of auth, any website can drive the API from a
victim's browser.

### 4.6 No rate limiting on login — MEDIUM

`POST /api/auth/login` has no throttling, lockout, or backoff. Combined with the weak
hashing in 4.3, credentials are brute-forceable at line speed.

### 4.7 Unauthenticated WebSockets — MEDIUM

- `GET /ws/feedback` — `main.py:887`
- `GET /ws/posture` — `main.py:1403`

Neither performs any handshake or origin check. The report's scope was HTTP routes only,
so these were never assessed.

### 4.8 Additional unauthenticated endpoints not listed — MEDIUM

- `GET /api/compare_sessions` — `main.py:918`
- `GET /api/reports/training_plan/{athlete_id}` — `main.py:977`

---

## 5. Deduplicated Risk Register

Consolidating 44 raw findings into the distinct issues that actually warrant work:

| # | Issue | Severity | Locations |
|---|---|---|---|
| 1 | No authentication layer / no token issuance | **CRITICAL** | `main.py:457-470` + all 31 routes |
| 2 | `assert_coach_owns_athlete` bypassable via omitted `coach_id` | **HIGH** | `main.py:280`, 933, 1033, 1194, 1214, 1287, 1310 |
| 3 | Unauth password reset → account takeover | **HIGH** | `main.py:547` |
| 4 | Unauth global session/data wipe | **HIGH** | `main.py:590` |
| 5 | StaticFiles leaks all session videos | **HIGH** | `main.py:205` |
| 6 | Broken password hashing (plaintext fallback, global salt, SHA-256) | **HIGH** | `main.py:42-51` |
| 7 | Unvalidated `role` field → self-service ADMIN creation | **HIGH** | `main.py:503-524` |
| 8 | Unauth user deletion | **HIGH** | `main.py:556` |
| 9 | CORS `*` + credentials | **MEDIUM** | `main.py:208` |
| 10 | No login rate limiting | **MEDIUM** | `main.py:457` |
| 11 | Insufficient `shot_id` filename sanitization | **MEDIUM** | `main.py:1185` |
| 12 | Unauthenticated WebSockets | **MEDIUM** | `main.py:887`, 1403 |

Four categories in the original report — **all 6 DESERIALIZATION findings and 2 of 3
MASS_ASSIGNMENT findings** — carry no risk and can be closed outright.

---

## 6. Calibration Notes

**What the report did well**
- Every line number is accurate against this commit.
- The AUTH and BOLA findings are technically correct and correctly located.
- It identified the single most important fact about the codebase: there is no auth.

**Where it overstated**
- Reported 1 root cause as 25 separate CRITICALs and 5 duplicate BFLA entries.
- Applied CRITICAL severity to low-impact endpoints (`/api/scatt-analysis`,
  `/api/user/{id}`) that expose no credentials or sensitive state.
- Used keyword-matching heuristics for DESERIALIZATION and MASS_ASSIGNMENT, producing
  6 findings with no technical basis.
- Missed the two highest-value issues (4.1 bypassable ownership check, 4.2 StaticFiles
  leak) despite them being directly adjacent to code it did analyze.

**How to use this document**
Treat the original report as a reliable endpoint inventory and an unreliable severity
assessment. The register in section 5 is the actionable version.