"""Finding store for saving and loading correlated security results."""

import json
from pathlib import Path
from typing import List, Optional
from trace_engine.findings.model import Finding


class FindingStore:
    """Manages persistence of correlated findings in the .trace directory."""

    def __init__(self, trace_dir: Path):
        self.trace_dir = trace_dir
        self.store_file = trace_dir / "findings.json"

    def save_findings(self, findings: List[Finding]) -> None:
        """Save a list of findings to JSON and generate markdown reports."""
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        data = [f.model_dump() for f in findings]
        with open(self.store_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        try:
            from trace_engine.output.markdown import generate_markdown_report
            project_name = self.trace_dir.parent.name if self.trace_dir.parent else "Application"
            md_content = generate_markdown_report(findings, project_name=project_name)
            (self.trace_dir / "findings.md").write_text(md_content, encoding="utf-8")

            workspace_root = self.trace_dir.parent
            if workspace_root and workspace_root.exists() and workspace_root != self.trace_dir:
                (workspace_root / "findings.md").write_text(md_content, encoding="utf-8")
        except Exception:
            pass

    def load_findings(self) -> List[Finding]:
        """Load findings from JSON file."""
        if not self.store_file.exists():
            return []
        try:
            with open(self.store_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [Finding.model_validate(item) for item in data]
        except Exception:
            return []

    def get_finding_by_id(self, finding_id: str) -> Optional[Finding]:
        """Retrieve finding by ID."""
        for f in self.load_findings():
            if f.id.lower() == finding_id.lower():
                return f
        return None
