"""Shared scan pipeline stages used by the CLI, the MCP server and verification.

Every command that scans (``scan``, ``audit``, MCP ``trace_scan``) runs the same
stages. Keeping them here means a new analyzer or guard is added once:

``discover``  ingest -> parse -> framework adapters (+ OpenAPI spec) -> routes
``run_probes`` live test packs with request budget, evidence log, catch-all guard
``finalize``  opt-in analyzers, suppression, baseline diff, CI gate, persistence
"""

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from trace_engine.findings.baseline import BaselineDiff, blocking_findings, diff_findings, load_baseline
from trace_engine.findings.correlate import EvidenceCorrelator
from trace_engine.findings.model import Finding
from trace_engine.findings.store import FindingStore
from trace_engine.findings.suppress import apply_suppressions, load_rules
from trace_engine.framework import get_adapters
from trace_engine.framework.base import Endpoint
from trace_engine.framework.openapi import SpecError, SpecInfo, find_spec, merge_with_code, parse_spec
from trace_engine.ingest.files import SourceFile
from trace_engine.parsing.parser import CodeParser, ParsedFile
from trace_engine.runtime.client import RequestBudgetExceeded, ScopedHttpClient
from trace_engine.runtime.soft404 import CatchAllBaseline, only_catch_all_evidence
from trace_engine.security.hypotheses import SecurityHypothesis, VulnerabilityCategory
from trace_engine.testpacks.base import TestContext, TestExecutionResult
from trace_engine.testpacks.registry import default_registry

# Categories whose findings only make sense when a live probe confirmed them.
RUNTIME_ONLY_CATEGORIES = {VulnerabilityCategory.RATE_LIMIT}
_NEURAL_ALIASES = {
    "AUTH": "AUTHENTICATION", "INJ": "INJECTION", "SQLI": "INJECTION", "MASS": "MASS_ASSIGNMENT",
    "TRAV": "PATH_TRAVERSAL", "TRAVERSAL": "PATH_TRAVERSAL", "DESER": "DESERIALIZATION",
}
_NEURAL_MIN = 0.5


# --------------------------------------------------------------------------- discovery

class Discovery(BaseModel):
    model_config = {"arbitrary_types_allowed": True}

    source_files: List[SourceFile] = Field(default_factory=list)
    parsed_files: List[ParsedFile] = Field(default_factory=list)
    endpoints: List[Endpoint] = Field(default_factory=list)
    failed_files: List[Tuple[str, str]] = Field(default_factory=list)
    spec: Optional[SpecInfo] = None
    inventory: Dict[str, List[str]] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)


def discover(
    project_dir: Path,
    source_files: List[SourceFile],
    *,
    spec: Optional[Path] = None,
    use_spec: bool = True,
) -> Discovery:
    """Parse ``source_files`` and extract routes; merge an API description if present."""
    parser = CodeParser()
    adapters = get_adapters()
    out = Discovery(source_files=list(source_files))
    code_endpoints: List[Endpoint] = []
    for sf in source_files:
        try:
            content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
            pf = parser.parse(sf.path, content, sf.language, absolute_path=sf.absolute_path)
            out.parsed_files.append(pf)
            for adapter in adapters:
                if adapter.can_handle(pf):
                    code_endpoints.extend(adapter.extract_endpoints(pf, content))
        except Exception as e:  # noqa: BLE001 - one unreadable file must not abort the scan
            out.failed_files.append((sf.path, f"{type(e).__name__}: {e}"))
    if out.failed_files:
        out.notes.append(f"{len(out.failed_files)} file(s) could not be analyzed (e.g. {out.failed_files[0][0]})")

    out.endpoints = code_endpoints
    if use_spec:
        spec_path = Path(spec) if spec else find_spec(project_dir)
        if spec_path is not None:
            try:
                info = parse_spec(spec_path, project_dir)
                out.spec = info
                out.endpoints, out.inventory = merge_with_code(code_endpoints, info.endpoints)
                out.notes.extend(info.warnings)
            except SpecError as e:
                out.notes.append(f"API spec ignored: {e}")
            except OSError as e:
                out.notes.append(f"API spec unreadable: {e}")
    return out


# --------------------------------------------------------------------------- probing

class ProbePlanItem(BaseModel):
    hypothesis: str
    category: str
    pack: str
    endpoint: str
    max_requests: int


class ProbeOutcome(BaseModel):
    findings: List[Finding] = Field(default_factory=list)
    executed: int = 0
    confirmed: int = 0
    budget_exhausted: bool = False
    not_probed: int = 0
    notes: List[str] = Field(default_factory=list)


_REQUESTS_PER_PACK = {"bola": 28, "rate_limit": 20}


def plan_probes(hypotheses: List[SecurityHypothesis]) -> List[ProbePlanItem]:
    """What a live run would send, without sending anything (``--dry-run``)."""
    plan = []
    for hyp in hypotheses:
        pack = default_registry.get(hyp.recommended_test_pack)
        if pack is None:
            continue
        plan.append(
            ProbePlanItem(
                hypothesis=hyp.id,
                category=hyp.category.value,
                pack=pack.name,
                endpoint=hyp.endpoint_display,
                max_requests=_REQUESTS_PER_PACK.get(pack.name, 4),
            )
        )
    return plan


def neural_scores_from(recommendations) -> Dict[Tuple[str, str], float]:
    """``(endpoint_id, CATEGORY) -> score`` from intelligence recommendations."""
    out: Dict[Tuple[str, str], float] = {}
    for rec in recommendations or []:
        for family, score in (getattr(rec, "securebert_scores", None) or {}).items():
            cat = _NEURAL_ALIASES.get(str(family).upper(), str(family).upper())
            if score >= _NEURAL_MIN:
                out[(rec.endpoint_id, cat)] = float(score)
    return out


def _demote(result: TestExecutionResult) -> TestExecutionResult:
    return result.model_copy(
        update={
            "confirmed": False,
            "confidence": 0.2,
            "summary": "Discounted: every success response matches the target's catch-all page. " + result.summary,
        }
    )


def run_probes(
    hypotheses: List[SecurityHypothesis],
    graph_model,
    client: ScopedHttpClient,
    context: TestContext,
    *,
    online: bool,
    catch_all: Optional[CatchAllBaseline] = None,
    neural: Optional[Dict[Tuple[str, str], float]] = None,
    on_result: Optional[Callable[[SecurityHypothesis, Optional[TestExecutionResult]], None]] = None,
) -> ProbeOutcome:
    """Execute each hypothesis' test pack (when ``online``) and correlate to findings."""
    correlator = EvidenceCorrelator()
    out = ProbeOutcome()
    for hyp in hypotheses:
        test_res: Optional[TestExecutionResult] = None
        pack = default_registry.get(hyp.recommended_test_pack)
        if pack and online and not out.budget_exhausted:
            try:
                out.executed += 1
                test_res = pack.execute(hyp, client, context)
            except RequestBudgetExceeded:
                out.budget_exhausted = True
                test_res = None
            except Exception:  # noqa: BLE001 - a failing pack degrades to static evidence
                test_res = None
            if test_res and test_res.confirmed and catch_all and only_catch_all_evidence(catch_all, test_res.observations):
                test_res = _demote(test_res)
        elif pack and online and out.budget_exhausted:
            out.not_probed += 1
        confirmed = bool(test_res and test_res.confirmed)
        if confirmed:
            out.confirmed += 1
        if on_result:
            on_result(hyp, test_res)
        if not confirmed and (
            hyp.category in RUNTIME_ONLY_CATEGORIES or hyp.endpoint_id.startswith("ep_openapi_")
        ):
            continue  # needs live proof: spec-only routes and rate limiting have no static evidence
        neural_score = (neural or {}).get((hyp.endpoint_id, hyp.category.value))
        finding = correlator.correlate(hyp, test_res, graph_model, neural_score=neural_score)
        if finding:
            out.findings.append(finding)
    if out.budget_exhausted:
        out.notes.append(
            f"request budget of {client.max_requests} reached; {out.not_probed} hypothesis(es) were not probed "
            f"(raise it with --max-requests or [runtime] max_requests)"
        )
    return out


# --------------------------------------------------------------------------- finalization

class ExtraChecks(BaseModel):
    secrets: bool = False
    cve: bool = False
    iac: bool = False
    detectors: bool = False
    sarif_in: List[Path] = Field(default_factory=list)

    @classmethod
    def all_checks(cls, sarif_in: Optional[List[Path]] = None) -> "ExtraChecks":
        return cls(secrets=True, cve=True, iac=True, detectors=True, sarif_in=sarif_in or [])


class Finalized(BaseModel):
    active: List[Finding] = Field(default_factory=list)
    suppressed: List[Finding] = Field(default_factory=list)
    suppression_reasons: Dict[str, str] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)
    diff: Optional[BaselineDiff] = None
    blocking: List[Finding] = Field(default_factory=list)


def _renumber_unique(findings: List[Finding]) -> None:
    """Keep IDs unique when several analyzers each start counting at 001."""
    seen: Dict[str, int] = {}
    for f in findings:
        if f.id in seen:
            seen[f.id] += 1
            f.id = f"{f.id}-{seen[f.id]}"
        else:
            seen[f.id] = 0


def finalize(
    findings: List[Finding],
    project_dir: Path,
    discovery: Discovery,
    *,
    extras: Optional[ExtraChecks] = None,
    suppress: bool = True,
    baseline: Optional[Path] = None,
    fail_on: Optional[str] = None,
    fail_confidence: str = "medium",
    include_fixtures: bool = False,
) -> Finalized:
    """Add opt-in analyzer findings, apply suppression, diff against a baseline, gate."""
    result = Finalized()
    all_findings = list(findings)
    extras = extras or ExtraChecks()

    if extras.sarif_in:
        from trace_engine.tools.sarif_ingest import ingest_sarif

        new, notes = ingest_sarif(extras.sarif_in, discovery.endpoints, all_findings)
        all_findings.extend(new)
        result.notes.extend(notes)
    if extras.secrets:
        from trace_engine.security.secrets import scan_secrets

        found, notes = scan_secrets(project_dir)
        all_findings.extend(found)
        result.notes.extend(notes)
    if extras.cve:
        from trace_engine.security.deps import scan_dependencies

        found, notes = scan_dependencies(project_dir)
        all_findings.extend(found)
        result.notes.extend(notes)
    if extras.iac:
        from trace_engine.security.iac import scan_iac

        found, notes = scan_iac(project_dir)
        all_findings.extend(found)
        result.notes.extend(notes)
    if extras.detectors:
        from trace_engine.security.detectors import scan_detectors

        found, notes = scan_detectors(discovery.source_files, discovery.endpoints)
        all_findings.extend(found)
        result.notes.extend(notes)
    _renumber_unique(all_findings)

    if suppress:
        rules, warnings = load_rules(project_dir)
        result.notes.extend(warnings)
        sup = apply_suppressions(all_findings, rules, root=project_dir)
        result.notes.extend(sup.warnings)
        result.active, result.suppressed, result.suppression_reasons = sup.active, sup.suppressed, sup.reasons
    else:
        result.active = all_findings

    gate_pool = result.active
    if baseline is not None:
        try:
            result.diff = diff_findings(result.active, load_baseline(baseline))
            gate_pool = result.diff.new
        except (ValueError, OSError) as e:
            result.notes.append(f"baseline {baseline} unreadable ({e}); gating on all findings")
    result.blocking = blocking_findings(
        gate_pool, fail_on, min_confidence=fail_confidence, include_fixtures=include_fixtures
    )
    return result


def persist(project_dir: Path, trace_dir: Path, final: Finalized) -> None:
    """Write the active findings (and the suppressed list) to ``.trace``."""
    FindingStore(trace_dir).save_findings(final.active)
    if final.suppressed:
        (trace_dir / "suppressed.json").write_text(
            json.dumps(
                [
                    {"fingerprint": f.fingerprint, "id": f.id, "title": f.title,
                     "reason": final.suppression_reasons.get(f.fingerprint, "")}
                    for f in final.suppressed
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
    try:
        root_trace = Path(".trace")
        root_trace.mkdir(parents=True, exist_ok=True)
        (root_trace / "last_scan_repo.txt").write_text(str(project_dir), encoding="utf-8")
        if project_dir != Path(".").resolve():
            FindingStore(root_trace).save_findings(final.active)
    except Exception:  # noqa: BLE001 - the workspace pointer is a convenience only
        pass
