"""CWE/type vocabulary shared by producers and the benchmark boundary.

Internal records use the CWE numbers from the PRD. The OWASP VulnerableApp
grader matches on its own canonical vocabulary (VulnerableApp
benchmarks/README.md and src/main/resources/scanner/sast/expectedIssues.csv);
the maps below translate at that boundary only. Joint file: changes are
stop-the-world, like common/record.py.
"""

from __future__ import annotations

from typing import Any

# Internal CWE -> `type` string written on records. Uses the grader's type
# names where the grader has one, so type matching works as well as CWE matching.
TYPE_NAMES = {
    89: "SQL Injection",
    79: "Reflected XSS",
    78: "Command Injection",
    601: "Open Redirect",
    22: "Path Traversal",
    798: "Hard-coded Credentials",
    327: "Cryptographic Failures",
    326: "Cryptographic Failures",
    330: "Weak Random Number Generation",
    916: "Weak Password Hashing",
    347: "Server Side Vulnerable Jwt",
}

# Internal CWE -> CWE the VulnerableApp grader expects. VulnerableApp labels
# OS command injection CWE-77; the PRD uses CWE-78.
GRADER_CWE = {78: 77}


def type_name(cwe: int) -> str:
    return TYPE_NAMES.get(cwe, f"CWE-{cwe}")


def grader_cwe(cwe: int) -> str:
    return f"CWE-{GRADER_CWE.get(cwe, cwe)}"


def to_grader_sast(findings: list[Any]) -> list[dict[str, Any]]:
    """SAST findings in the VulnerableApp grader's JSON shape (not SARIF)."""
    return [
        {"filePath": f.file, "line": f.line, "cwe": grader_cwe(f.cwe), "type": f.type}
        for f in findings
        if f.source == "sast" and f.file is not None and f.line is not None
    ]
