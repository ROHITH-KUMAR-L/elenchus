"""Measurement-only: score the servlet SAST adapter against OWASP BenchmarkJava.

    uv run python scripts/benchmark_java_score.py <benchmark-repo-root>

The repo root holds `src/main/java` and `expectedresults-1.2.csv`. BenchmarkJava
is a static hold-out (dynamic scanning of a hold-out is not allowed), so this is
SAST-only. The answer key marks each test case real/safe per CWE with no line
number, so scoring is per-test-case TP/FP (the standard Benchmark metric), not
the per-line match used for VulnerableApp. This file is a measurement harness,
not scanner logic, and never feeds detection.
"""

from __future__ import annotations

import collections
import csv
import sys
from pathlib import Path

from producers.sast.code_index import build_code_index
from producers.sast.static_stage import ScanTarget, run_static

COVERED_CWES = {22, 78, 79, 89}  # the classes our catalogue targets


def main(repo_root: str) -> int:
    root = Path(repo_root)
    src = root / "src/main/java"

    expected: dict[str, tuple[int, bool]] = {}
    with open(root / "expectedresults-1.2.csv") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            name, _category, real, cwe = row[0], row[1], row[2], int(row[3])
            expected[name] = (cwe, real.strip().lower() == "true")

    index = build_code_index(str(src), "servlet")
    target = ScanTarget(str(src), "http://localhost/", "benchmark", "servlet")
    reported: dict[str, set[int]] = collections.defaultdict(set)
    for finding in run_static(target, index):
        stem = Path(finding.file).stem
        if stem in expected:
            reported[stem].add(finding.cwe)

    per: dict[int, dict[str, int]] = collections.defaultdict(
        lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    )
    for name, (cwe, real) in expected.items():
        if cwe not in COVERED_CWES:
            continue
        flagged = cwe in reported.get(name, set())
        cell = per[cwe]
        if real and flagged:
            cell["tp"] += 1
        elif real and not flagged:
            cell["fn"] += 1
        elif not real and flagged:
            cell["fp"] += 1
        else:
            cell["tn"] += 1

    print(f"{'cwe':>5} {'TP':>5}{'FN':>5}{'FP':>5}{'TN':>5}  {'TPR':>6} {'FPR':>6} {'Youden':>7}")
    total: collections.Counter[str] = collections.Counter()

    def _rates(c: dict[str, int]) -> tuple[float, float]:
        tpr = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 0.0
        fpr = c["fp"] / (c["fp"] + c["tn"]) if c["fp"] + c["tn"] else 0.0
        return tpr, fpr

    for cwe in sorted(per):
        c = per[cwe]
        total.update(c)
        tpr, fpr = _rates(c)
        print(
            f"{cwe:>5} {c['tp']:>5}{c['fn']:>5}{c['fp']:>5}{c['tn']:>5}  "
            f"{tpr:>6.2f} {fpr:>6.2f} {tpr - fpr:>7.2f}"
        )
    tpr, fpr = _rates(total)
    print(
        f"{'ALL':>5} {total['tp']:>5}{total['fn']:>5}{total['fp']:>5}{total['tn']:>5}  "
        f"{tpr:>6.2f} {fpr:>6.2f} {tpr - fpr:>7.2f}"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: uv run python scripts/benchmark_java_score.py <benchmark-repo-root>")
    raise SystemExit(main(sys.argv[1]))
