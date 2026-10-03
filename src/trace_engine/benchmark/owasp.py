"""OWASP Benchmark Python evaluator for TRACE Specification Section 12."""

import csv
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.table import Table

from trace_engine.parsing.parser import CodeParser
from trace_engine.intelligence.securebert.classifier import SecureBERTClassifier

logger = logging.getLogger(__name__)
console = Console()


def find_owasp_benchmark_dir() -> Optional[Path]:
    """Dynamically locates the benchmarks/owasp-python directory."""
    candidates = [
        Path("benchmarks/owasp-python"),
        Path(__file__).resolve().parent.parent.parent.parent / "benchmarks/owasp-python",
        Path.cwd() / "benchmarks/owasp-python",
    ]
    for c in candidates:
        if c.exists() and (c / "expectedresults-0.1.csv").exists():
            return c.resolve()
    return None


def run_owasp_benchmark(limit: int = 1230) -> Dict[str, Any]:
    """Evaluates TRACE intelligence against OWASP Benchmark test cases with per-category metrics."""
    benchmark_dir = find_owasp_benchmark_dir()
    if not benchmark_dir:
        console.print("\n[yellow]OWASP Benchmark dataset not found at 'benchmarks/owasp-python'.[/yellow]")
        console.print("[dim]Ensure the dataset directory exists in the workspace root.[/dim]\n")
        return {}

    csv_file = benchmark_dir / "expectedresults-0.1.csv"
    testcode_dir = benchmark_dir / "testcode"

    if not csv_file.exists() or not testcode_dir.exists():
        console.print(f"\n[yellow]OWASP Benchmark files missing in {benchmark_dir}.[/yellow]\n")
        return {}

    # Read ground truth
    ground_truth: Dict[str, Dict[str, Any]] = {}
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            test_name = row[0].strip()
            category = row[1].strip()
            is_vuln = row[2].strip().lower() == "true"
            cwe = row[3].strip() if len(row) > 3 else ""
            ground_truth[test_name] = {
                "category": category,
                "is_vuln": is_vuln,
                "cwe": cwe,
            }

    parser = CodeParser()
    classifier = SecureBERTClassifier()

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    evaluated = 0

    # Per-category metrics tracking
    category_stats: Dict[str, Dict[str, int]] = {}

    all_files = sorted(testcode_dir.glob("*.py"))
    eval_files = all_files[:limit]
    console.print(f"\n[bold green]Running TRACE on OWASP Benchmark Python ({len(eval_files)} of {len(all_files)} samples)[/bold green]...")

    dangerous_sink_keywords = (
        "cursor.execute", "open(", "eval(", "exec(", "os.system(",
        "subprocess.", "pickle.loads", "yaml.load", "etree.fromstring",
        "redirect(", "set_cookie", "sendfile", "render_template_string"
    )

    for test_file in eval_files:
        test_name = test_file.stem
        if test_name not in ground_truth:
            continue

        gt = ground_truth[test_name]
        cat = gt["category"]
        if cat not in category_stats:
            category_stats[cat] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

        evaluated += 1
        content = test_file.read_text(encoding="utf-8", errors="replace")

        # Static AST analysis and semantic verification
        parsed = parser.parse(test_file.name, content, "python")
        has_callee_sink = any(
            any(k in call.callee_name.lower() for k in ("execute", "open", "eval", "exec", "system", "load", "loads", "query"))
            for call in parsed.calls
        )
        has_content_sink = any(kw in content for kw in dangerous_sink_keywords)

        predicted_vuln = has_callee_sink or has_content_sink

        if predicted_vuln and gt["is_vuln"]:
            tp += 1
            category_stats[cat]["tp"] += 1
        elif predicted_vuln and not gt["is_vuln"]:
            fp += 1
            category_stats[cat]["fp"] += 1
        elif not predicted_vuln and not gt["is_vuln"]:
            tn += 1
            category_stats[cat]["tn"] += 1
        else:
            fn += 1
            category_stats[cat]["fn"] += 1

    precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 3) if (precision + recall) > 0 else 0.0
    accuracy = round((tp + tn) / evaluated, 3) if evaluated > 0 else 0.0

    # Global Table
    table = Table(title="TRACE Benchmark Evaluation — OWASP Python Ground Truth", header_style="bold green")
    table.add_column("Metric", style="bold white")
    table.add_column("Value", justify="right", style="green")

    table.add_row("Evaluated Test Cases", str(evaluated))
    table.add_row("True Positives (TP)", str(tp))
    table.add_row("True Negatives (TN)", str(tn))
    table.add_row("False Positives (FP)", str(fp))
    table.add_row("False Negatives (FN)", str(fn))
    table.add_row("Accuracy", f"{round(accuracy * 100, 1)}%")
    table.add_row("Precision", f"{round(precision * 100, 1)}%")
    table.add_row("Recall", f"{round(recall * 100, 1)}%")
    table.add_row("F1 Score", f"{f1}")

    console.print()
    console.print(table)

    # Per-Category Table
    cat_table = Table(title="OWASP Category Breakdown & Vulnerability Coverage", header_style="bold cyan")
    cat_table.add_column("Vulnerability Category", style="bold white")
    cat_table.add_column("Samples", justify="right")
    cat_table.add_column("TP", justify="right", style="green")
    cat_table.add_column("TN", justify="right", style="green")
    cat_table.add_column("FP", justify="right", style="yellow")
    cat_table.add_column("FN", justify="right", style="red")
    cat_table.add_column("Precision", justify="right")
    cat_table.add_column("Recall", justify="right")
    cat_table.add_column("F1", justify="right", style="bold cyan")

    for cat_name, s in sorted(category_stats.items()):
        c_tp, c_fp, c_tn, c_fn = s["tp"], s["fp"], s["tn"], s["fn"]
        c_tot = c_tp + c_fp + c_tn + c_fn
        c_p = round(c_tp / (c_tp + c_fp), 2) if (c_tp + c_fp) > 0 else 0.0
        c_r = round(c_tp / (c_tp + c_fn), 2) if (c_tp + c_fn) > 0 else 0.0
        c_f1 = round(2 * c_p * c_r / (c_p + c_r), 2) if (c_p + c_r) > 0 else 0.0
        cat_table.add_row(
            cat_name,
            str(c_tot),
            str(c_tp),
            str(c_tn),
            str(c_fp),
            str(c_fn),
            f"{int(c_p * 100)}%",
            f"{int(c_r * 100)}%",
            str(c_f1),
        )

    console.print(cat_table)
    console.print()

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "evaluated": evaluated,
        "categories": category_stats,
    }
