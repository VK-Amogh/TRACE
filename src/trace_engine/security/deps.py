"""Dependency vulnerability scan against OSV.dev (opt-in: ``--cve``).

Parses pinned versions from common lockfiles and manifests, asks the public
OSV database about each (name, version), and reports one finding per
vulnerable package. This is the only analyzer that contacts a third party:
only package names and versions are sent, never source code. Results are
cached for 24 hours so reruns and offline use stay fast.
"""

import json
import re
import time
import tomllib
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel

from trace_engine.findings.factory import make_finding
from trace_engine.findings.model import Finding, FindingConfidence, Severity
from trace_engine.ingest.textfiles import iter_text_files

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
CACHE_TTL = 24 * 3600
MAX_DETAIL_LOOKUPS = 60
BATCH_SIZE = 500
MAX_PACKAGES = 5000


class Dep(BaseModel):
    ecosystem: str
    name: str
    version: str
    file: str


class OsvError(Exception):
    """OSV could not be reached or returned an unusable answer."""


# --------------------------------------------------------------------------- parsers

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)")


def parse_requirements(text: str, file: str) -> List[Dep]:
    deps = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0]
        m = _REQ_RE.match(line)
        if m:
            deps.append(Dep(ecosystem="PyPI", name=m.group(1).lower().replace("_", "-"), version=m.group(2), file=file))
    return deps


def parse_pipfile_lock(text: str, file: str) -> List[Dep]:
    doc = json.loads(text)
    deps = []
    for section in ("default", "develop"):
        for name, meta in (doc.get(section) or {}).items():
            version = str((meta or {}).get("version", "")).lstrip("=")
            if version:
                deps.append(Dep(ecosystem="PyPI", name=name.lower().replace("_", "-"), version=version, file=file))
    return deps


def parse_toml_packages(text: str, file: str, ecosystem: str) -> List[Dep]:
    doc = tomllib.loads(text)
    return [
        Dep(ecosystem=ecosystem, name=str(p["name"]).lower() if ecosystem == "PyPI" else str(p["name"]),
            version=str(p["version"]), file=file)
        for p in doc.get("package", [])
        if p.get("name") and p.get("version")
    ]


def parse_package_lock(text: str, file: str) -> List[Dep]:
    doc = json.loads(text)
    out: Dict[Tuple[str, str], Dep] = {}
    for path, meta in (doc.get("packages") or {}).items():
        if not path or "node_modules/" not in path:
            continue
        name = path.rsplit("node_modules/", 1)[1]
        version = (meta or {}).get("version")
        if name and version:
            out[(name, version)] = Dep(ecosystem="npm", name=name, version=str(version), file=file)

    def walk(deps: Dict[str, Any]) -> None:
        for name, meta in (deps or {}).items():
            version = (meta or {}).get("version")
            if version and re.match(r"^\d", str(version)):
                out.setdefault((name, str(version)), Dep(ecosystem="npm", name=name, version=str(version), file=file))
            walk((meta or {}).get("dependencies") or {})

    walk(doc.get("dependencies") or {})
    return list(out.values())


def parse_go_mod(text: str, file: str) -> List[Dep]:
    deps = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        body = line[len("require "):] if line.startswith("require ") else (line if in_block else "")
        parts = body.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            deps.append(Dep(ecosystem="Go", name=parts[0], version=parts[1], file=file))
    return deps


def parse_composer_lock(text: str, file: str) -> List[Dep]:
    doc = json.loads(text)
    return [
        Dep(ecosystem="Packagist", name=str(p["name"]), version=str(p["version"]).lstrip("v"), file=file)
        for section in ("packages", "packages-dev")
        for p in doc.get(section, []) or []
        if p.get("name") and p.get("version")
    ]


def parse_gemfile_lock(text: str, file: str) -> List[Dep]:
    deps = []
    for line in text.splitlines():
        m = re.match(r"^    ([A-Za-z0-9._-]+) \(([0-9][^)]*)\)\s*$", line)
        if m:
            deps.append(Dep(ecosystem="RubyGems", name=m.group(1), version=m.group(2), file=file))
    return deps


def collect_dependencies(repo: Path) -> Tuple[List[Dep], List[str]]:
    """Dependencies from every recognized manifest under ``repo``."""
    def accept(name: str) -> bool:
        low = name.lower()
        return (
            (low.startswith("requirements") and low.endswith(".txt"))
            or low in {"pipfile.lock", "poetry.lock", "package-lock.json", "go.mod", "cargo.lock",
                       "composer.lock", "gemfile.lock"}
        )

    deps: Dict[Tuple[str, str, str], Dep] = {}
    notes: List[str] = []
    for rel, _path, text in iter_text_files(repo, accept):
        low = rel.rsplit("/", 1)[-1].lower()
        try:
            if low.startswith("requirements"):
                found = parse_requirements(text, rel)
            elif low == "pipfile.lock":
                found = parse_pipfile_lock(text, rel)
            elif low == "poetry.lock":
                found = parse_toml_packages(text, rel, "PyPI")
            elif low == "package-lock.json":
                found = parse_package_lock(text, rel)
            elif low == "go.mod":
                found = parse_go_mod(text, rel)
            elif low == "cargo.lock":
                found = parse_toml_packages(text, rel, "crates.io")
            elif low == "composer.lock":
                found = parse_composer_lock(text, rel)
            else:
                found = parse_gemfile_lock(text, rel)
        except (ValueError, KeyError, tomllib.TOMLDecodeError) as e:
            notes.append(f"deps: could not parse {rel}: {e}")
            continue
        for d in found:
            deps.setdefault((d.ecosystem, d.name, d.version), d)
    ordered = sorted(deps.values(), key=lambda d: (d.ecosystem, d.name, d.version))
    if len(ordered) > MAX_PACKAGES:
        notes.append(f"deps: checking the first {MAX_PACKAGES} of {len(ordered)} packages")
        ordered = ordered[:MAX_PACKAGES]
    return ordered, notes


# --------------------------------------------------------------------------- OSV client

def _default_post(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    import httpx

    try:
        resp = httpx.post(url, json=payload, timeout=15.0)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:  # noqa: BLE001
        raise OsvError(str(e)) from e


def _default_get(url: str) -> Dict[str, Any]:
    import httpx

    try:
        resp = httpx.get(url, timeout=15.0)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:  # noqa: BLE001
        raise OsvError(str(e)) from e


class OsvClient:
    """Cached OSV lookups; ``post``/``get`` are injectable for tests and offline mirrors."""

    def __init__(
        self,
        cache_path: Optional[Path] = None,
        post: Callable[[str, Dict[str, Any]], Dict[str, Any]] = _default_post,
        get: Callable[[str], Dict[str, Any]] = _default_get,
        now: Callable[[], float] = time.time,
    ):
        self.cache_path = cache_path
        self.post, self.get, self.now = post, get, now
        self._cache: Dict[str, Any] = {}
        if cache_path and cache_path.is_file():
            try:
                self._cache = json.loads(cache_path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                self._cache = {}

    def _fresh(self, key: str) -> Optional[Any]:
        entry = self._cache.get(key)
        if entry and self.now() - entry.get("ts", 0) < CACHE_TTL:
            return entry["value"]
        return None

    def _store(self, key: str, value: Any) -> None:
        self._cache[key] = {"ts": self.now(), "value": value}

    def save(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache), encoding="utf-8")
        except OSError:
            pass

    def vulnerabilities(self, deps: Iterable[Dep]) -> Dict[Tuple[str, str, str], List[str]]:
        """Advisory IDs per ``(ecosystem, name, version)``."""
        result: Dict[Tuple[str, str, str], List[str]] = {}
        pending: List[Dep] = []
        for d in deps:
            key = f"q|{d.ecosystem}|{d.name}|{d.version}"
            cached = self._fresh(key)
            if cached is not None:
                if cached:
                    result[(d.ecosystem, d.name, d.version)] = cached
            else:
                pending.append(d)
        for i in range(0, len(pending), BATCH_SIZE):
            chunk = pending[i : i + BATCH_SIZE]
            payload = {
                "queries": [
                    {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in chunk
                ]
            }
            answer = self.post(OSV_BATCH_URL, payload)
            results = answer.get("results", [])
            if len(results) != len(chunk):
                raise OsvError("OSV returned a malformed batch response")
            for d, res in zip(chunk, results):
                ids = sorted({v["id"] for v in (res or {}).get("vulns", []) if "id" in v})
                self._store(f"q|{d.ecosystem}|{d.name}|{d.version}", ids)
                if ids:
                    result[(d.ecosystem, d.name, d.version)] = ids
        return result

    def details(self, vuln_id: str) -> Dict[str, Any]:
        key = f"v|{vuln_id}"
        cached = self._fresh(key)
        if cached is not None:
            return cached
        data = self.get(OSV_VULN_URL + vuln_id)
        self._store(key, data)
        return data


_SEVERITY_WORDS = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
                   "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def severity_of(detail: Dict[str, Any]) -> Severity:
    word = str((detail.get("database_specific") or {}).get("severity", "")).upper()
    return _SEVERITY_WORDS.get(word, Severity.MEDIUM)


def fixed_versions(detail: Dict[str, Any], name: str) -> List[str]:
    fixed = []
    for aff in detail.get("affected", []) or []:
        if str((aff.get("package") or {}).get("name", "")).lower() != name.lower():
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixed.append(str(ev["fixed"]))
    return sorted(set(fixed))


def scan_dependencies(
    repo: Path,
    client: Optional[OsvClient] = None,
) -> Tuple[List[Finding], List[str]]:
    """One finding per vulnerable package. Network failures become notes."""
    deps, notes = collect_dependencies(repo)
    if not deps:
        return [], notes + ["deps: no pinned dependencies found in recognized manifests"]
    client = client or OsvClient(cache_path=Path.home() / ".trace" / "cache" / "osv.json")
    try:
        vulnerable = client.vulnerabilities(deps)
    except OsvError as e:
        return [], notes + [f"deps: OSV lookup failed ({e}); dependency check skipped"]
    findings: List[Finding] = []
    lookups = 0
    by_key = {(d.ecosystem, d.name, d.version): d for d in deps}
    for key, ids in sorted(vulnerable.items()):
        dep = by_key[key]
        sevs, fixes, summaries = [], [], []
        for vid in ids[:8]:
            detail: Dict[str, Any] = {}
            if lookups < MAX_DETAIL_LOOKUPS:
                try:
                    detail = client.details(vid)
                    lookups += 1
                except OsvError:
                    detail = {}
            if detail:
                sevs.append(severity_of(detail))
                fixes.extend(fixed_versions(detail, dep.name))
                if detail.get("summary"):
                    summaries.append(f"{vid}: {detail['summary'][:120]}")
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        severity = max(sevs, key=order.index) if sevs else Severity.MEDIUM
        evidence = [
            f"{dep.name}@{dep.version} ({dep.ecosystem}) has {len(ids)} known advisor{'y' if len(ids) == 1 else 'ies'}: "
            + ", ".join(ids[:8]) + (" ..." if len(ids) > 8 else ""),
            *summaries[:3],
        ]
        if fixes:
            evidence.append(f"Fixed in: {', '.join(sorted(set(fixes))[:5])}")
        evidence.append("Reachability from your routes is not assessed; confirm the vulnerable feature is used")
        findings.append(
            make_finding(
                finding_id=f"TR-DEP-{len(findings) + 1:03d}",
                category="DEPENDENCY",
                title=f"Known vulnerabilities in {dep.name}",
                endpoint=f"{dep.name}@{dep.version}",
                severity=severity,
                confidence=FindingConfidence.HIGH,
                evidence=evidence,
                file=dep.file,
                line=1,
                notes="Package version matched public OSV advisories.",
            )
        )
    client.save()
    return findings, notes
