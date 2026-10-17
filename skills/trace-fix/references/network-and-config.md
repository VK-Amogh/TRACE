# Network and configuration playbook

Covers `TR-SSRF` and `TR-CORS`.

## SSRF: server-side request forgery

**Invariant:** the server only requests destinations on an explicit
allow-list, and the address actually connected to is checked, not just the
string the user sent.

Best fix: do not fetch user-supplied URLs. Accept an id/choice and map it to
a server-side configured URL. If a user URL is a real requirement:

1. Allow-list scheme (`https` only) and host (exact names or a domain suffix
   you control). Reject userinfo (`user@host`), non-standard ports, and
   unusual encodings.
2. Resolve the host and reject loopback, private (RFC 1918), link-local
   (`169.254.0.0/16`, includes cloud metadata `169.254.169.254`), unique-local
   IPv6, multicast and reserved ranges, including IPv4-mapped IPv6 and
   integer/hex/octal IP spellings.
3. Disable redirects, or re-validate every hop.
4. Connect to the validated IP (pin it) so DNS cannot change between check
   and use (DNS rebinding / TOCTOU); set short timeouts and a response size cap.
5. Do not return raw response bodies or detailed errors to the user.
6. Defense in depth: egress firewall/proxy that denies internal ranges.

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.partner.example"}

def check_url(raw: str) -> str:
    u = urlparse(raw)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS or u.username or u.port not in (None, 443):
        raise ValueError("destination not allowed")
    for *_, sockaddr in socket.getaddrinfo(u.hostname, 443, type=socket.SOCK_STREAM):
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("destination resolves to a prohibited address")
    return raw

# then: httpx.get(url, follow_redirects=False, timeout=5)
```

Note: the check above alone leaves a small resolve-then-connect window;
pinning the resolved IP in the HTTP client closes it. TRACE's own
`ScopeGuard` documents the same limitation.

```javascript
// Node: same shape. Resolve with dns.promises.lookup({all:true}), test each
// address with a library such as `ipaddr.js`, then request with redirect: 'error'.
```

Blocklists of strings (`localhost`, `127.0.0.1`, `10.`) are bypassable
(`127.1`, `0x7f000001`, `[::ffff:127.0.0.1]`, DNS names that resolve to
internal IPs, redirects). Treat them as unacceptable fixes.

Tests: `http://127.0.0.1`, `http://169.254.169.254/`, `http://[::1]/`,
`http://2130706433/`, a name resolving to a private IP, and a redirect to
an internal address are all rejected; an allowed partner URL works.

## CORS

**Invariant:** only named origins may make credentialed cross-origin
requests.

- Replace `Access-Control-Allow-Origin: *` or reflected `Origin` with an
  allow-list lookup; echo the origin only when it matches exactly.
- Never combine a wildcard or reflected origin with
  `Access-Control-Allow-Credentials: true`.
- Do not allow `null` origin. Add `Vary: Origin` when the header varies.
- Limit methods and headers to what clients need.

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],   # exact, no "*" with credentials
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```

```javascript
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
```

Match origins by exact string or a strict parsed host check; substring or
`endsWith(".example.com")` tests are bypassable (`evil-example.com`).

Tests: request with `Origin: https://evil.example` gets no
`Access-Control-Allow-Origin`; the real app origin does; credentials are only
allowed for it.
