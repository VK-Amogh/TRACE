"""Opt-in analyzers: secrets, dependencies (OSV), IaC, detectors, external SARIF."""

import json
from pathlib import Path

from trace_engine.findings.model import Finding, FindingConfidence, Severity
from trace_engine.framework.base import Endpoint
from trace_engine.ingest.files import SourceFile
from trace_engine.parsing.locations import SourceLocation
from trace_engine.security.deps import (
    OsvClient,
    OsvError,
    collect_dependencies,
    parse_go_mod,
    parse_package_lock,
    parse_requirements,
    scan_dependencies,
)
from trace_engine.security.detectors import scan_detectors
from trace_engine.security.iac import scan_iac
from trace_engine.security.secrets import entropy, is_placeholder, scan_secrets
from trace_engine.tools.sarif_ingest import ingest_sarif, load_sarif


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- secrets ---------------------------------------------------------------

AWS = "AKIAIOSFODNN7EXAMPLQ"
PW = "Tr0ub4dor&3xK9vQz"


def test_secrets_found_redacted_and_stable(tmp_path: Path):
    write(tmp_path, "config/.env", f"AWS_KEY={AWS}\nDB_PASSWORD='{PW}'\nOTHER=changeme-please\n")
    write(tmp_path, "src/app.py", 'api_key = "your_api_key_here"\npassword = os.environ["PW"]\n')
    findings, notes = scan_secrets(tmp_path)
    titles = sorted(f.title for f in findings)
    assert titles == ["Hardcoded secret: AWS access key ID", "Hardcoded secret: Hardcoded credential assignment"]
    blob = json.dumps([f.model_dump() for f in findings])
    assert AWS not in blob and PW not in blob, "secret values must never be stored"
    assert all(f.category == "SECRETS" and f.cwe == "CWE-798" for f in findings)
    assert findings[0].endpoint.startswith("config/.env#")
    again, _ = scan_secrets(tmp_path)
    assert [f.fingerprint for f in again] == [f.fingerprint for f in findings]


def test_secret_moves_do_not_change_fingerprint(tmp_path: Path):
    write(tmp_path, "a.py", f'token = "x"\nkey = "{AWS}"\n')
    first = scan_secrets(tmp_path)[0][0].fingerprint
    write(tmp_path, "a.py", f'# moved\n\n\nkey = "{AWS}"\n')
    assert scan_secrets(tmp_path)[0][0].fingerprint == first


def test_secret_helpers_and_private_keys(tmp_path: Path):
    assert entropy("aaaa") == 0 and entropy("a1B2c3D4e5") > 3
    assert is_placeholder("${DB_PASSWORD}") and is_placeholder("aaaaaaaaaa") and not is_placeholder(PW)
    write(tmp_path, "id_rsa.key", "-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    write(tmp_path, "package-lock.json", f'{{"x": "{AWS}"}}')
    findings, _ = scan_secrets(tmp_path)
    assert [f.severity for f in findings] == [Severity.CRITICAL], "lockfiles are skipped, keys are critical"


def test_fixture_secrets_are_labelled(tmp_path: Path):
    write(tmp_path, "tests/fixtures/.env", f"AWS_KEY={AWS}\n")
    f = scan_secrets(tmp_path)[0][0]
    assert f.is_fixture and f.priority_score < 40


# --- dependencies ----------------------------------------------------------

def test_manifest_parsers():
    reqs = "Django==3.2.0  # web\nrequests[socks]==2.25.0 ; python_version>'3'\nflask>=2\n-r other.txt\n"
    assert [(d.name, d.version) for d in parse_requirements(reqs, "r.txt")] == [("django", "3.2.0"), ("requests", "2.25.0")]
    lock = json.dumps({
        "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}, "node_modules/a/node_modules/b": {"version": "1.0.0"}},
        "dependencies": {"left-pad": {"version": "1.3.0"}},
    })
    names = sorted(d.name for d in parse_package_lock(lock, "package-lock.json"))
    assert names == ["b", "left-pad", "lodash"]
    gomod = "module x\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgolang.org/x/net v0.1.0 // indirect\n)\nrequire github.com/c/d v0.0.1\n"
    assert sorted(d.name for d in parse_go_mod(gomod, "go.mod")) == ["github.com/a/b", "github.com/c/d", "golang.org/x/net"]


def test_collect_dependencies_dedupes_and_skips_ignored_dirs(tmp_path: Path):
    write(tmp_path, "requirements.txt", "django==3.2.0\n")
    write(tmp_path, "svc/requirements-dev.txt", "django==3.2.0\npytest==7.0.0\n")
    write(tmp_path, "node_modules/x/package-lock.json", '{"packages": {"node_modules/evil": {"version": "1.0.0"}}}')
    deps, notes = collect_dependencies(tmp_path)
    assert sorted((d.name, d.version) for d in deps) == [("django", "3.2.0"), ("pytest", "7.0.0")]


def osv_fakes(calls):
    def post(url, payload):
        calls.append(("post", len(payload["queries"])))
        return {"results": [
            {"vulns": [{"id": "GHSA-aaaa"}, {"id": "CVE-2024-1"}]} if q["package"]["name"] == "django" else {}
            for q in payload["queries"]
        ]}

    def get(url):
        calls.append(("get", url.rsplit("/", 1)[-1]))
        return {"summary": "SQL injection in QuerySet", "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"name": "django"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.2.5"}]}]}]}

    return post, get


def test_scan_dependencies_reports_vulnerable_packages_and_caches(tmp_path: Path):
    write(tmp_path, "requirements.txt", "django==3.2.0\nrequests==2.31.0\n")
    calls = []
    post, get = osv_fakes(calls)
    cache = tmp_path / "cache" / "osv.json"
    client = OsvClient(cache_path=cache, post=post, get=get)
    findings, _ = scan_dependencies(tmp_path, client)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "DEPENDENCY" and f.endpoint == "django@3.2.0" and f.severity == Severity.HIGH
    assert any("3.2.5" in e for e in f.static_evidence) and any("GHSA-aaaa" in e for e in f.static_evidence)
    assert cache.is_file()

    calls.clear()
    again, _ = scan_dependencies(tmp_path, OsvClient(cache_path=cache, post=post, get=get))
    assert len(again) == 1 and calls == [], "second run is served from the cache"


def test_scan_dependencies_degrades_offline(tmp_path: Path):
    write(tmp_path, "requirements.txt", "django==3.2.0\n")

    def down(*a, **k):
        raise OsvError("no network")

    findings, notes = scan_dependencies(tmp_path, OsvClient(post=down, get=down))
    assert findings == [] and any("OSV lookup failed" in n for n in notes)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert "no pinned dependencies" in scan_dependencies(empty, OsvClient(post=down, get=down))[1][0]


# --- IaC -------------------------------------------------------------------

def test_iac_rules(tmp_path: Path):
    write(tmp_path, "Dockerfile", "FROM python\nADD https://x.io/a.tgz /a\nRUN curl http://x | sh\nENV API_TOKEN=abc123\nRUN chmod 777 /app\n")
    write(tmp_path, "ok/Dockerfile", "FROM python:3.12-slim\nUSER app\n")
    write(tmp_path, "docker-compose.yml", "services:\n  db:\n    privileged: true\n    network_mode: host\n    ports:\n      - \"5432:5432\"\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n")
    write(tmp_path, ".github/workflows/ci.yml", (
        "on: pull_request_target\npermissions: write-all\njobs:\n  b:\n    steps:\n"
        "      - uses: evil/action@main\n"
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: echo \"${{ github.event.pull_request.title }}\"\n"
    ))
    write(tmp_path, "infra/main.tf", 'resource "aws_security_group" "g" {\n  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\nresource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n')
    write(tmp_path, "k8s/pod.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - securityContext:\n      privileged: true\n      runAsUser: 0\n")
    findings, _ = scan_iac(tmp_path)
    titles = {f.title for f in findings}
    for expected in (
        "Container runs as root", "Unpinned base image", "Remote file fetched with ADD", "Remote script piped to a shell",
        "Secret baked into image layer", "World-writable permissions", "Privileged container", "Host network mode",
        "Docker socket mounted", "Database port published on all interfaces", "Script injection in workflow run step",
        "Workflow grants write-all permissions", "Third-party action pinned to a branch",
        "pull_request_target checks out untrusted code", "Security group open to the internet",
        "Database publicly accessible", "Privileged pod", "Pod runs as root",
    ):
        assert expected in titles, expected
    assert not any(f.endpoint == "ok/Dockerfile" for f in findings), "a hardened Dockerfile stays quiet"
    assert all(f.category == "MISCONFIG" for f in findings)


# --- detectors -------------------------------------------------------------

def test_detectors_and_open_redirect(tmp_path: Path):
    app = write(tmp_path, "app.py", (
        "import jwt, requests\n"
        "@app.route('/go')\n"
        "def go():\n"
        "    return redirect(request.args.get('next'))\n"
        "data = jwt.decode(tok, key, options={'verify_signature': False})\n"
        "requests.get(u, verify=False)\n"
        "app.run(debug=True)\n"
        "t = jwt.sign(p, 'secret')\n"
    ))
    sf = SourceFile(path="app.py", absolute_path=str(app), language="python", size_bytes=1, line_count=8, sha256="x")
    ep = Endpoint(id="e1", method="GET", path="/go", handler_name="go",
                  source=SourceLocation(file=str(app), line_start=2, line_end=2))
    findings, _ = scan_detectors([sf], [ep])
    titles = {f.title for f in findings}
    assert {"JWT signature verification disabled", "TLS certificate verification disabled", "Debug mode enabled",
            "JWT signed with a short literal secret", "Open redirect"} <= titles
    redirect = next(f for f in findings if f.title == "Open redirect")
    assert redirect.category == "OPEN_REDIRECT" and redirect.endpoint == "GET /go"


# --- external SARIF ----------------------------------------------------------

def sarif_doc(file, line, rule="python.flask.sqli", cwe="CWE-89", level="error"):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": [{"id": rule, "properties": {"tags": [f"{cwe}: SQL Injection"]}}]}},
        "results": [{"ruleId": rule, "level": level, "message": {"text": "tainted query"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": line}}}]}],
    }]}


def test_external_sarif_maps_to_endpoints_and_boosts_duplicates(tmp_path: Path):
    ep = Endpoint(id="e1", method="GET", path="/q", handler_name="q",
                  source=SourceLocation(file="C:/repo/app/api.py", line_start=10, line_end=10))
    sarif = write(tmp_path, "semgrep.sarif", json.dumps(sarif_doc("app/api.py", 14)))
    assert load_sarif(sarif)[0].cwes == ["89"]
    new, notes = ingest_sarif([sarif], [ep], [])
    assert len(new) == 1 and notes == []
    f = new[0]
    assert f.category == "INJECTION" and f.endpoint == "GET /q" and f.severity == Severity.HIGH
    assert f.confidence == FindingConfidence.MEDIUM and "Semgrep" in f.title

    existing = Finding(id="TR-INJ-001", title="t", category="INJECTION", severity=Severity.CRITICAL,
                       confidence=FindingConfidence.MEDIUM, endpoint="GET /q", correlation_notes="n", remediation="r")
    merged, _ = ingest_sarif([sarif], [ep], [existing])
    assert merged == [] and existing.confidence == FindingConfidence.HIGH
    assert any("Semgrep" in e for e in existing.static_evidence)


def test_bad_sarif_is_reported_not_raised(tmp_path: Path):
    bad = write(tmp_path, "bad.sarif", "{nope")
    new, notes = ingest_sarif([bad], [], [])
    assert new == [] and "could not read" in notes[0]
    far = write(tmp_path, "far.sarif", json.dumps(sarif_doc("other/file.py", 5, rule="x.y", cwe="CWE-9999")))
    unmatched, _ = ingest_sarif([far], [], [])
    assert unmatched[0].category == "EXTERNAL" and unmatched[0].endpoint == "other/file.py"
