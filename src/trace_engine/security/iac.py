"""Infrastructure and delivery configuration checks (opt-in: ``--iac``).

A small, high-signal ruleset for Dockerfiles, Docker Compose files, GitHub
Actions workflows, Terraform and Kubernetes manifests. Line-based on purpose:
no YAML dependency and no false confidence about semantics TRACE does not
model. Each rule names the secure alternative in its evidence.
"""

import re
from pathlib import Path
from typing import List, Optional, Tuple

from trace_engine.findings.factory import make_finding
from trace_engine.findings.model import Finding, FindingConfidence, Severity
from trace_engine.ingest.textfiles import iter_text_files

# (title, severity, evidence, line)
Hit = Tuple[str, Severity, str, int]

_DB_PORTS = {"3306", "5432", "6379", "27017", "9200", "11211", "1433", "5984"}
_SENSITIVE_ENV = re.compile(r"(?i)(password|secret|token|api[_-]?key)")
_RUN_FIELDS = r"(?:title|body|name|message|ref|label|head_ref|default_branch|email)"
_INJECTABLE = re.compile(r"\$\{\{\s*github\.(?:event\.[A-Za-z_.\[\]*]*" + _RUN_FIELDS + r"\b|head_ref)")


def _kind(rel: str, text: str) -> Optional[str]:
    name = rel.rsplit("/", 1)[-1].lower()
    low = rel.lower()
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return "dockerfile"
    if re.match(r"^(docker-)?compose(\.[\w-]+)?\.ya?ml$", name):
        return "compose"
    if ".github/workflows/" in low and name.endswith((".yml", ".yaml")):
        return "workflow"
    if name.endswith(".tf"):
        return "terraform"
    if name.endswith((".yml", ".yaml")) and "apiVersion:" in text and re.search(r"^kind:\s*\w+", text, re.M):
        return "kubernetes"
    return None


def check_dockerfile(text: str) -> List[Hit]:
    hits: List[Hit] = []
    lines = text.splitlines()
    has_user = any(re.match(r"^\s*USER\s+(?!root\b|0\b)\S+", l, re.I) for l in lines)
    if lines and not has_user:
        hits.append(("Container runs as root", Severity.MEDIUM,
                     "No non-root USER instruction; add `USER <unprivileged>` before the entrypoint", 1))
    for i, l in enumerate(lines, start=1):
        s = l.strip()
        if re.match(r"^FROM\s+(?!scratch)(?:--platform=\S+\s+)?([^\s:@]+)(?::latest)?(?:\s+AS\s+\S+)?$", s, re.I):
            hits.append(("Unpinned base image", Severity.LOW,
                         "Base image uses the implicit or `latest` tag; pin a version or digest", i))
        if re.match(r"^ADD\s+https?://", s, re.I):
            hits.append(("Remote file fetched with ADD", Severity.MEDIUM,
                         "ADD from a URL is unverified; use curl/wget with a checksum, or COPY", i))
        if re.search(r"(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh\b", s):
            hits.append(("Remote script piped to a shell", Severity.HIGH,
                         "Downloads and executes code without verification; fetch, verify a checksum, then run", i))
        m = re.match(r"^(?:ENV|ARG)\s+([A-Za-z0-9_]+)[= ]\s*(\S+)", s)
        if m and _SENSITIVE_ENV.search(m.group(1)) and not m.group(2).startswith(("$", "${")) and m.group(2) not in ('""', "''"):
            hits.append(("Secret baked into image layer", Severity.HIGH,
                         f"{m.group(1)} is set to a literal in the Dockerfile; pass it at runtime or use build secrets", i))
        if re.search(r"chmod\s+(-R\s+)?0?777\b", s):
            hits.append(("World-writable permissions", Severity.MEDIUM, "chmod 777 grants everyone write access", i))
        if re.match(r"^EXPOSE\s+(?:.*\s)?22\b", s):
            hits.append(("SSH port exposed", Severity.LOW, "EXPOSE 22 suggests an SSH daemon in the container", i))
    return hits


def check_compose(text: str) -> List[Hit]:
    hits: List[Hit] = []
    for i, l in enumerate(text.splitlines(), start=1):
        s = l.strip()
        if re.match(r"^privileged:\s*true\b", s):
            hits.append(("Privileged container", Severity.HIGH, "privileged: true disables container isolation", i))
        if re.match(r"^network_mode:\s*[\"']?host[\"']?", s):
            hits.append(("Host network mode", Severity.MEDIUM, "network_mode: host bypasses network isolation", i))
        if "/var/run/docker.sock" in s:
            hits.append(("Docker socket mounted", Severity.HIGH,
                         "Mounting the Docker socket gives the container control of the host", i))
        if re.search(r"cap_add:.*\b(ALL|SYS_ADMIN)\b", s) or re.match(r"^-\s*(ALL|SYS_ADMIN)\s*$", s):
            hits.append(("Excessive Linux capabilities", Severity.HIGH, "Grant only the specific capabilities needed", i))
        m = re.match(r"^-\s*[\"']?(?:0\.0\.0\.0:)?(\d+):(\d+)(?:/\w+)?[\"']?\s*$", s)
        if m and m.group(2) in _DB_PORTS and ("127.0.0.1" not in s):
            hits.append(("Database port published on all interfaces", Severity.MEDIUM,
                         f"Port {m.group(1)} is reachable from outside the host; bind to 127.0.0.1", i))
    return hits


def check_workflow(text: str) -> List[Hit]:
    hits: List[Hit] = []
    lines = text.splitlines()
    pr_target = any(re.search(r"\bpull_request_target\b", l) for l in lines)
    in_run, run_indent = False, 0
    for i, l in enumerate(lines, start=1):
        indent = len(l) - len(l.lstrip())
        s = l.strip()
        if in_run and s and indent <= run_indent:
            in_run = False
        m = re.match(r"^(\s*)-?\s*run:\s*(.*)$", l)
        if m:
            in_run, run_indent = True, len(m.group(1))
            rest = m.group(2)
            if _INJECTABLE.search(rest):
                hits.append(("Script injection in workflow run step", Severity.HIGH,
                             "Untrusted event data is interpolated into a shell command; pass it via an env var", i))
        elif in_run and _INJECTABLE.search(l):
            hits.append(("Script injection in workflow run step", Severity.HIGH,
                         "Untrusted event data is interpolated into a shell command; pass it via an env var", i))
        if re.match(r"^permissions:\s*write-all\b", s):
            hits.append(("Workflow grants write-all permissions", Severity.HIGH,
                         "Use least-privilege `permissions:` per job", i))
        u = re.match(r"^-?\s*uses:\s*([\w.-]+)/([\w./-]+)@(main|master|latest|dev|develop)\b", s)
        if u and u.group(1).lower() not in {"actions", "github"}:
            hits.append(("Third-party action pinned to a branch", Severity.MEDIUM,
                         f"{u.group(1)}/{u.group(2)}@{u.group(3)} can change under you; pin a commit SHA", i))
        if pr_target and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", s):
            hits.append(("pull_request_target checks out untrusted code", Severity.CRITICAL,
                         "Running PR code with write permissions and secrets lets forks take over the repository", i))
    return hits


def check_terraform(text: str) -> List[Hit]:
    hits: List[Hit] = []
    lines = text.splitlines()
    for i, l in enumerate(lines, start=1):
        s = l.strip()
        if re.search(r"cidr_blocks\s*=\s*\[[^\]]*\"0\.0\.0\.0/0\"", s):
            window = "\n".join(lines[max(0, i - 8) : i])
            if re.search(r"\bingress\b", window) and not re.search(r"\begress\b[^\n]*\{[^}]*\Z", window):
                hits.append(("Security group open to the internet", Severity.MEDIUM,
                             "Ingress from 0.0.0.0/0; restrict to known CIDR ranges", i))
        if re.match(r"^publicly_accessible\s*=\s*true", s):
            hits.append(("Database publicly accessible", Severity.HIGH, "publicly_accessible = true", i))
        if re.match(r"^acl\s*=\s*\"public-read(-write)?\"", s):
            hits.append(("Public bucket ACL", Severity.HIGH, "Bucket ACL grants public access", i))
        if re.match(r"^(storage_)?encrypted\s*=\s*false", s):
            hits.append(("Encryption disabled", Severity.MEDIUM, "Storage encryption is explicitly disabled", i))
    return hits


def check_kubernetes(text: str) -> List[Hit]:
    hits: List[Hit] = []
    for i, l in enumerate(text.splitlines(), start=1):
        s = l.strip()
        if re.match(r"^privileged:\s*true\b", s):
            hits.append(("Privileged pod", Severity.HIGH, "privileged: true disables container isolation", i))
        if re.match(r"^(hostNetwork|hostPID|hostIPC):\s*true\b", s):
            hits.append(("Pod shares host namespaces", Severity.MEDIUM, "Remove host namespace sharing", i))
        if re.match(r"^allowPrivilegeEscalation:\s*true\b", s):
            hits.append(("Privilege escalation allowed", Severity.MEDIUM, "Set allowPrivilegeEscalation: false", i))
        if re.match(r"^runAsUser:\s*0\b", s):
            hits.append(("Pod runs as root", Severity.MEDIUM, "runAsUser: 0; use a non-root UID", i))
    return hits


_CHECKS = {
    "dockerfile": check_dockerfile, "compose": check_compose, "workflow": check_workflow,
    "terraform": check_terraform, "kubernetes": check_kubernetes,
}


def scan_iac(repo: Path) -> Tuple[List[Finding], List[str]]:
    def accept(name: str) -> bool:
        low = name.lower()
        return (
            low.startswith(("dockerfile", "docker-compose", "compose"))
            or low.endswith((".dockerfile", ".yml", ".yaml", ".tf"))
        )

    findings: List[Finding] = []
    seen = set()
    for rel, _path, text in iter_text_files(repo, accept):
        kind = _kind(rel, text)
        if not kind:
            continue
        for title, severity, evidence, line in _CHECKS[kind](text):
            key = (rel, title)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                make_finding(
                    finding_id=f"TR-IAC-{len(findings) + 1:03d}",
                    category="MISCONFIG",
                    title=title,
                    endpoint=rel,
                    severity=severity,
                    confidence=FindingConfidence.HIGH,
                    evidence=[f"{rel}:{line}: {evidence}"],
                    file=rel,
                    line=line,
                    notes=f"Detected by the {kind} configuration ruleset.",
                )
            )
    return findings, []
