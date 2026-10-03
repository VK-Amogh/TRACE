"""Importers and adapters for external security research datasets (Big-Vul, D2A, CVEfixes, Juliet)."""

import csv
import json
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger(__name__)


class JulietImporter:
    """Parser for NIST Juliet Test Suite v1.3 SARIF and source directories."""

    def import_sarif(self, sarif_file: Path) -> List[Tuple[str, List[str]]]:
        samples: List[Tuple[str, List[str]]] = []
        if not sarif_file.exists():
            return samples

        try:
            with open(sarif_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            runs = data.get("runs", [])
            for run in runs:
                results = run.get("results", [])
                for res in results:
                    rule_id = res.get("ruleId", "")
                    msg = res.get("message", {}).get("text", "")
                    samples.append((msg, [rule_id]))
        except Exception as e:
            logger.debug(f"Juliet SARIF parse error: {e}")
        return samples


class BigVulImporter:
    """Parser for Big-Vul dataset (CVE-mapped vulnerable functions)."""

    def import_csv(self, csv_file: Path, limit: int = 1000) -> List[Tuple[str, List[str]]]:
        samples: List[Tuple[str, List[str]]] = []
        if not csv_file.exists():
            return samples

        try:
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if i >= limit:
                        break
                    func_before = row.get("func_before", "")
                    vuln = row.get("vul", "0") == "1"
                    cve = row.get("CVE-ID", "CWE-Unknown")
                    if func_before:
                        samples.append((func_before, [cve] if vuln else []))
        except Exception as e:
            logger.debug(f"Big-Vul CSV parse error: {e}")
        return samples


class CVEfixesImporter:
    """Parser for CVEfixes commit diffs and patch pairs."""

    def import_jsonl(self, jsonl_file: Path, limit: int = 1000) -> List[Tuple[str, List[str]]]:
        samples: List[Tuple[str, List[str]]] = []
        if not jsonl_file.exists():
            return samples

        try:
            with open(jsonl_file, "r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    item = json.loads(line)
                    code = item.get("code", "")
                    cwe = item.get("cwe_id", "INJECTION")
                    if code:
                        samples.append((code, [cwe]))
        except Exception as e:
            logger.debug(f"CVEfixes parse error: {e}")
        return samples
