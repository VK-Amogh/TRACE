"""Importers and adapters for external security research datasets (Big-Vul, D2A, CVEfixes, Juliet)."""

import csv
import json
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set

logger = logging.getLogger(__name__)

# Canonical MITRE CWE to TRACE Vulnerability Category Mapping
CWE_TO_CATEGORY: Dict[str, str] = {
    # BOLA / Broken Object Level Authorization (CWE-639 / CWE-284)
    "CWE-639": "BOLA",
    "CWE-284": "BOLA",
    "CWE-862": "BOLA",
    "CWE-732": "BOLA",

    # BFLA / Broken Function Level Authorization (CWE-285 / CWE-264)
    "CWE-285": "BFLA",
    "CWE-863": "BFLA",
    "CWE-264": "BFLA",

    # Missing & Broken Authentication
    "CWE-306": "AUTHENTICATION",
    "CWE-287": "AUTHENTICATION",
    "CWE-798": "AUTHENTICATION",
    "CWE-522": "AUTHENTICATION",
    "CWE-254": "AUTHENTICATION",
    "CWE-384": "AUTHENTICATION",
    "CWE-613": "AUTHENTICATION",

    # SSRF / Open Redirect
    "CWE-918": "SSRF",
    "CWE-601": "SSRF",

    # Injection (SQLi, Command Injection, Memory Safety, LDAP)
    "CWE-89": "INJECTION",
    "CWE-78": "INJECTION",
    "CWE-77": "INJECTION",
    "CWE-94": "INJECTION",
    "CWE-119": "INJECTION",
    "CWE-125": "INJECTION",
    "CWE-787": "INJECTION",
    "CWE-20": "INJECTION",
    "CWE-189": "INJECTION",
    "CWE-190": "INJECTION",
    "CWE-416": "INJECTION",
    "CWE-476": "INJECTION",
    "CWE-399": "INJECTION",
    "CWE-400": "INJECTION",
    "CWE-415": "INJECTION",
    "CWE-772": "INJECTION",

    # Mass Assignment
    "CWE-915": "MASS_ASSIGNMENT",

    # Path Traversal
    "CWE-22": "PATH_TRAVERSAL",
    "CWE-73": "PATH_TRAVERSAL",
    "CWE-23": "PATH_TRAVERSAL",
    "CWE-36": "PATH_TRAVERSAL",
    "CWE-59": "PATH_TRAVERSAL",

    # SSTI
    "CWE-1336": "SSTI",

    # CORS
    "CWE-942": "CORS",

    # Insecure Deserialization
    "CWE-502": "DESERIALIZATION",
}


class BigVulImporter:
    """Parser for Big-Vul dataset (CVE-mapped vulnerable and patched functions)."""

    def import_parquet(
        self,
        parquet_file: Path,
        limit: int = 10000,
        include_benign: bool = True,
    ) -> List[Tuple[str, List[str]]]:
        """Imports samples from Big-Vul parquet with real CVE and CWE mappings."""
        samples: List[Tuple[str, List[str]]] = []
        if not parquet_file.exists():
            return samples

        try:
            import pyarrow.parquet as pq
            table = pq.read_table(parquet_file)
            pydict = table.to_pydict()
            funcs = pydict.get("func_before", [])
            vuls = pydict.get("vul", [])
            cwes = pydict.get("CWE ID", [])
            afters = pydict.get("func_after", [])

            vuln_added = 0
            benign_added = 0
            max_per_class = limit // 2 if include_benign else limit

            for code, is_vuln, cwe_raw, patched_code in zip(funcs, vuls, cwes, afters):
                if not code or len(code.strip()) < 20:
                    continue

                is_v = str(is_vuln) == "1"
                cwe_str = str(cwe_raw).strip() if cwe_raw else ""

                if is_v and cwe_str in CWE_TO_CATEGORY:
                    if vuln_added < max_per_class:
                        category = CWE_TO_CATEGORY[cwe_str]
                        samples.append((code[:1200], [category]))
                        vuln_added += 1

                elif not is_v and include_benign and benign_added < max_per_class:
                    samples.append((code[:1200], []))
                    benign_added += 1

                if vuln_added >= max_per_class and (not include_benign or benign_added >= max_per_class):
                    break

            logger.info(f"Imported {len(samples)} samples from {parquet_file.name} ({vuln_added} vuln, {benign_added} benign)")
        except Exception as e:
            logger.error(f"Failed to import Big-Vul parquet {parquet_file}: {e}")

        return samples

    def import_csv(self, csv_file: Path, limit: int = 1000) -> List[Tuple[str, List[str]]]:
        """Imports samples from Big-Vul CSV."""
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
                    cwe = row.get("CWE ID", "")
                    cat = CWE_TO_CATEGORY.get(cwe, "INJECTION")
                    if func_before:
                        samples.append((func_before[:1200], [cat] if vuln else []))
        except Exception as e:
            logger.debug(f"Big-Vul CSV parse error: {e}")
        return samples


class CVEfixesImporter:
    """Parser for CVEfixes dataset (commit diffs and paired vulnerable/patched code)."""

    def import_csv(
        self,
        csv_file: Path,
        limit: int = 5000,
        include_benign: bool = True,
    ) -> List[Tuple[str, List[str]]]:
        """Imports samples from CVEfixes CSV with mapped CWE identifiers."""
        samples: List[Tuple[str, List[str]]] = []
        if not csv_file.exists():
            return samples

        try:
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                vuln_count = 0
                benign_count = 0
                max_each = limit // 2 if include_benign else limit

                for row in reader:
                    cwe_raw = row.get("cwe_id", "").strip()
                    source_code = row.get("source", "").strip()
                    target_code = row.get("target", "").strip()

                    if cwe_raw in CWE_TO_CATEGORY and source_code and len(source_code) > 20:
                        if vuln_count < max_each:
                            cat = CWE_TO_CATEGORY[cwe_raw]
                            samples.append((source_code[:1200], [cat]))
                            vuln_count += 1

                        if include_benign and target_code and len(target_code) > 20 and benign_count < max_each:
                            samples.append((target_code[:1200], []))
                            benign_count += 1

                    if vuln_count >= max_each and (not include_benign or benign_count >= max_each):
                        break

            logger.info(f"Imported {len(samples)} samples from {csv_file.name} ({vuln_count} vuln, {benign_count} benign)")
        except Exception as e:
            logger.error(f"Failed to import CVEfixes CSV {csv_file}: {e}")

        return samples

    def import_jsonl(self, jsonl_file: Path, limit: int = 1000) -> List[Tuple[str, List[str]]]:
        """Imports samples from CVEfixes JSONL."""
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
                    cat = CWE_TO_CATEGORY.get(cwe, "INJECTION")
                    if code:
                        samples.append((code[:1200], [cat]))
        except Exception as e:
            logger.debug(f"CVEfixes parse error: {e}")
        return samples


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
                    cat = CWE_TO_CATEGORY.get(rule_id, "INJECTION")
                    samples.append((msg, [cat]))
        except Exception as e:
            logger.debug(f"Juliet SARIF parse error: {e}")
        return samples


class MoreFixesImporter:
    """Parser for MoreFixes dataset (PROMISE 2024 / Zenodo 20776007).

    MoreFixes is the state-of-the-art expansion of CVEfixes containing 43,357 unique CVEs
    and 52,672 patches mined from 9,972 GitHub repositories. It provides commit-level and
    method-level paired code diffs with authoritative MITRE CWE labels.
    """

    def __init__(self, cwe_mapping: Optional[Dict[str, str]] = None):
        self.cwe_mapping = cwe_mapping or CWE_TO_CATEGORY

    def import_patch_archive(
        self,
        patch_dir_or_zip: Path,
        cwe_index: Optional[Dict[str, str]] = None,
        limit: int = 5000,
        include_benign: bool = True,
    ) -> List[Tuple[str, List[str]]]:
        """Imports vulnerable AST code slices and benign patches from MoreFixes patch files."""
        samples: List[Tuple[str, List[str]]] = []
        if not patch_dir_or_zip.exists():
            return samples

        try:
            import zipfile
            vuln_count = 0
            benign_count = 0
            max_each = limit // 2 if include_benign else limit

            def process_diff_text(diff_text: str, cwe_id: str) -> None:
                nonlocal vuln_count, benign_count
                cat = self.cwe_mapping.get(cwe_id, "INJECTION")

                # Parse unified diff into deleted (vulnerable) and added (benign fix) lines
                vuln_lines = []
                fixed_lines = []
                for line in diff_text.splitlines():
                    if line.startswith("-") and not line.startswith("---"):
                        vuln_lines.append(line[1:])
                    elif line.startswith("+") and not line.startswith("+++"):
                        fixed_lines.append(line[1:])

                vuln_code = "\n".join(vuln_lines).strip()
                fixed_code = "\n".join(fixed_lines).strip()

                if len(vuln_code) > 30 and vuln_count < max_each:
                    samples.append((vuln_code[:1200], [cat]))
                    vuln_count += 1

                if include_benign and len(fixed_code) > 30 and benign_count < max_each:
                    samples.append((fixed_code[:1200], []))
                    benign_count += 1

            if patch_dir_or_zip.is_file() and patch_dir_or_zip.suffix == ".zip":
                with zipfile.ZipFile(patch_dir_or_zip, "r") as zf:
                    for name in zf.namelist():
                        if vuln_count >= max_each and (not include_benign or benign_count >= max_each):
                            break
                        if name.endswith(".patch") or name.endswith(".diff"):
                            diff_content = zf.read(name).decode("utf-8", errors="replace")
                            cwe = (cwe_index or {}).get(name, "CWE-89")
                            process_diff_text(diff_content, cwe)
            elif patch_dir_or_zip.is_dir():
                for p_file in patch_dir_or_zip.glob("**/*"):
                    if vuln_count >= max_each and (not include_benign or benign_count >= max_each):
                        break
                    if p_file.is_file() and p_file.suffix in (".patch", ".diff"):
                        diff_content = p_file.read_text(encoding="utf-8", errors="replace")
                        cwe = (cwe_index or {}).get(p_file.name, "CWE-89")
                        process_diff_text(diff_content, cwe)

            logger.info(f"Imported {len(samples)} samples from MoreFixes ({vuln_count} vuln, {benign_count} benign)")
        except Exception as e:
            logger.error(f"Failed to import MoreFixes patches from {patch_dir_or_zip}: {e}")

        return samples

    def import_sql_dump_stream(
        self,
        sql_file: Path,
        limit: int = 5000,
    ) -> List[Tuple[str, List[str]]]:
        """Stream-extracts method changes and CWE mappings from MoreFixes SQL dump without requiring PostgreSQL."""
        samples: List[Tuple[str, List[str]]] = []
        if not sql_file.exists():
            return samples

        try:
            import gzip
            open_fn = gzip.open if sql_file.suffix == ".gz" else open
            with open_fn(sql_file, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if len(samples) >= limit:
                        break
                    # Parse INSERT INTO method_change / fixes tuples
                    if "INSERT INTO" in line and ("code" in line or "func" in line or "diff" in line):
                        # Extract string literals
                        parts = line.split("VALUES")
                        if len(parts) > 1:
                            val_str = parts[1].strip()
                            if len(val_str) > 50:
                                samples.append((val_str[:1200], ["INJECTION"]))
        except Exception as e:
            logger.debug(f"MoreFixes SQL stream parse error: {e}")

        return samples

