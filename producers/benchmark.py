"""Score our producers against OWASP VulnerableApp's ground truth.

SAST is scored offline against src/main/resources/scanner/sast/expectedIssues.csv
with the grader's own matching rule (VulnerableApp benchmarks/README.md): same
normalised file, same line, and the same CWE or type. Practice only: this
measures VulnerableApp, not the organisers' app.

    uv run python -m producers.benchmark sast <VulnerableApp root>
"""

from __future__ import annotations

import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

from common.record import ScanTarget, normalize_file
from common.vocabulary import to_grader_sast
from producers.sast.semgrep_runner import run_sast
from producers.sast.spring_routes import route_map

EXPECTED_CSV = "src/main/resources/scanner/sast/expectedIssues.csv"


def load_expected(root: Path) -> list[dict[str, str]]:
    with open(root / EXPECTED_CSV, newline="") as handle:
        return [
            {"cwe": row["CWE"].strip().upper(), "type": row["Vulnerability Type"].strip().lower(),
             "file": normalize_file(row["File"].strip()), "line": int(row["Line"])}
            for row in csv.DictReader(handle)
        ]


def score_sast(expected: list[dict[str, str]], reported: list[dict]) -> dict:
    """Grader matching: exact file and line, plus CWE or type."""
    matched = set()
    unmatched = []
    for item in reported:
        file, line = normalize_file(item["filePath"]), item["line"]
        cwe, kind = item["cwe"].upper(), item["type"].lower()
        hits = [
            i for i, e in enumerate(expected)
            if e["file"] == file and e["line"] == line and (e["cwe"] == cwe or e["type"] == kind)
        ]
        matched.update(hits)
        if not hits:
            unmatched.append(item)
    return {"matched": matched, "unmatched": unmatched}


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "sast":
        sys.exit("usage: python -m producers.benchmark sast <VulnerableApp root>")
    root = Path(argv[2])
    target = ScanTarget(str(root), "http://localhost:9090/VulnerableApp", "benchmark", "spring-mvc")
    findings = run_sast(target, route_map(target))
    reported = to_grader_sast(findings)
    expected = load_expected(root)
    result = score_sast(expected, reported)

    by_cwe = defaultdict(lambda: [0, 0])
    for i, e in enumerate(expected):
        by_cwe[e["cwe"]][1] += 1
        by_cwe[e["cwe"]][0] += i in result["matched"]
    reported_cwes = {r["cwe"] for r in reported}

    print(f"Findings reported: {len(reported)}")
    print(f"Expected issues:   {len(expected)}  matched: {len(result['matched'])}")
    print("\nRecall for CWEs we report:")
    for cwe in sorted(reported_cwes, key=lambda c: int(c.split("-")[1])):
        hit, total = by_cwe.get(cwe, [0, 0])
        print(f"  {cwe:8} {hit:3}/{total:<3}")
    in_scope = [c for c in reported_cwes if c in by_cwe]
    hit = sum(by_cwe[c][0] for c in in_scope)
    total = sum(by_cwe[c][1] for c in in_scope)
    if total:
        print(f"  {'total':8} {hit:3}/{total:<3} ({100 * hit / total:.0f}%)")
    print(f"\nReported but not in ground truth: {len(result['unmatched'])}")
    for cwe, count in sorted(Counter(u["cwe"] for u in result["unmatched"]).items()):
        print(f"  {cwe:8} {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
