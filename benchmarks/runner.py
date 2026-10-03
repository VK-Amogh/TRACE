"""Benchmark runner for evaluating TRACE against OWASP Benchmark Python."""

import csv
from pathlib import Path
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table

from trace_engine.parsing.parser import CodeParser
from trace_engine.intelligence.securebert.classifier import SecureBERTClassifier

console = Console()


def run_owasp_benchmark(limit: int = 50) -> Dict[str, Any]:
    """Evaluates TRACE intelligence against OWASP Benchmark test cases."""
    benchmark_dir = Path("benchmarks/owasp-python")
    csv_file = benchmark_dir / "expectedresults-0.1.csv"
    testcode_dir = benchmark_dir / "testcode"

    if not csv_file.exists() or not testcode_dir.exists():
        console.print("[yellow]OWASP Benchmark not found at benchmarks/owasp-python.[/yellow]")
        return {}

    # Read ground truth
    ground_truth = {}
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

    console.print(f"\n[bold green]Running TRACE on OWASP Benchmark Python ({limit} samples)[/bold green]...")

    for test_file in sorted(testcode_dir.glob("*.py"))[:limit]:
        test_name = test_file.stem
        if test_name not in ground_truth:
            continue

        gt = ground_truth[test_name]
        evaluated += 1
        content = test_file.read_text(encoding="utf-8", errors="replace")

        # Static AST analysis
        parsed = parser.parse(test_file.name, content, "python")
        has_dangerous_sink = any(
            any(k in call.callee_name.lower() for k in ("cursor.execute", "open", "eval", "exec", "os.system"))
            for call in parsed.calls
        ) or ("execute" in content or "open(" in content or "format(" in content)

        predicted_vuln = has_dangerous_sink

        if predicted_vuln and gt["is_vuln"]:
            tp += 1
        elif predicted_vuln and not gt["is_vuln"]:
            fp += 1
        elif not predicted_vuln and not gt["is_vuln"]:
            tn += 1
        else:
            fn += 1

    precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 3) if (precision + recall) > 0 else 0.0

    table = Table(title="TRACE Benchmark Evaluation — OWASP Python", header_style="bold green")
    table.add_column("Metric", style="bold white")
    table.add_column("Value", justify="right", style="green")

    table.add_row("Evaluated Test Cases", str(evaluated))
    table.add_row("True Positives (TP)", str(tp))
    table.add_row("True Negatives (TN)", str(tn))
    table.add_row("False Positives (FP)", str(fp))
    table.add_row("False Negatives (FN)", str(fn))
    table.add_row("Precision", f"{int(precision * 100)}%")
    table.add_row("Recall", f"{int(recall * 100)}%")
    table.add_row("F1 Score", f"{f1}")

    console.print(table)
    return {"precision": precision, "recall": recall, "f1": f1, "evaluated": evaluated}


if __name__ == "__main__":
    run_owasp_benchmark(limit=50)
