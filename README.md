# SAST and DAST Correlation

CyberForge hackathon entry. Spec: [docs/prd.md](docs/prd.md).

Status: design stage. Nothing has been built, run or measured yet.

## 1. What it is

The tool scans Python source code (SAST) and the running app (DAST). It correlates the two sets of findings into one prioritised list. Each real bug appears once, with its code line and its runtime proof.

## 2. Approach

Current plan. Items marked `[TODO: confirm at kickoff]` depend on the test app.

| Area | Decision |
|---|---|
| Target language | Python (Flask/FastAPI). `[TODO: confirm at kickoff]` |
| SAST, injection classes | Semgrep in taint mode. Sanitiser-aware, so parameterised-query decoys are not reported. |
| SAST, simple patterns | Bandit and regex rules for code-only findings such as hard-coded secrets. |
| DAST | OWASP ZAP, seeded from the route map instead of blind crawling. |
| Route map | URL → handler function → file and line range. Built with Python's `ast` (tree-sitter if the framework needs it). This is the correlation join key. |
| Correlation | Our own logic. See below. |
| Runtime verdicts | Deterministic oracles only. See below. |
| Labels | Confirmed / Code-only / Runtime-only (FR-7). |

### Correlation rule

Link a DAST finding to a SAST finding when both hold:

1. The CWE matches.
2. The DAST route's handler line range contains the SAST finding's file and line.

Where both findings carry a parameter name, it must also match. This avoids wrong links when one handler has several bugs.

- Linked pair → **Confirmed**
- SAST finding with no link → **Code-only**
- DAST finding with no code location → **Runtime-only** (e.g. missing security headers)

Duplicate merge key and re-run behaviour (FR-6): `[TODO]`

### Oracles

Every runtime verdict comes from a deterministic check. The AI never decides that an exploit worked.

| Type | Oracle |
|---|---|
| SQL injection | Database error in response, or time delay |
| XSS | Unique marker reflected unescaped in response |
| Command injection | Time delay |
| Open redirect | `Location` header points to our marker host |

Delay thresholds and marker formats: `[TODO]`

## 3. Vulnerability types covered

| Type | CWE | Found by | Status |
|---|---|---|---|
| SQL injection | CWE-89 | Code and runtime | Committed |
| Cross-site scripting | CWE-79 | Code and runtime | Committed |
| Command injection | CWE-78 | Code and runtime | Committed |
| Open redirect | CWE-601 | Code and runtime | Committed |
| Path traversal | CWE-22 | Code and runtime | Stretch |

Hard-coded secrets (CWE-798) are code-only. The Bandit/regex pass reports them as Code-only findings.

## 4. Finding schema

This schema is frozen first. Every component reads and writes it. Example values below are illustrative, taken from the PRD.

```json
{
  "run_id": "example-run",
  "source": "dast",
  "cwe": 89,
  "route": "GET /api/orders",
  "file": "orders.py",
  "line": 88,
  "param": "id",
  "payload": "1'",
  "evidence": {
    "oracle": "db_error",
    "request": "GET /api/orders?id=1'",
    "response_excerpt": "..."
  },
  "label": "Confirmed",
  "risk_score": null
}
```

- `source`: `sast` or `dast`.
- `file` and `line`: filled by SAST, or by the route map for a linked DAST finding.
- `route`, `param`, `payload`: filled by DAST, or by the route map for a SAST finding.
- `risk_score`: severity and ease of exploitation (FR-9). Formula `[TODO]`.
- Severity field and storage (SQLite or file): `[TODO]`

## 5. Architecture

```
source code  --> Semgrep, Bandit       --+
source code  --> route map (ast)         +--> common finding format
running app  --> ZAP (seeded by routes)--+              |
                                                        v
                                    correlation engine (uses route map)
                                                        |
                                                        v
                                                prioritised list
```

## 6. Getting started

Prerequisites:

- Docker and Docker Compose
- The organisers' test app, running on your own machine

The test app runs separately, from the organisers' own Compose file. Our DAST scanner points only at that app. Do not point it at any other host.

Steps:

1. Start the organisers' test app: `[TODO: per organisers' instructions]`
2. Clone this repo: `[TODO]`
3. Set the target app URL and source path: `[TODO]`
4. Start the tool with Docker Compose: `[TODO]`
5. Run a scan and read the report: `[TODO]`

Interface (CLI, API or page, FR-10): `[TODO]`

## 7. Open-source scanners used

The challenge rules require this list. The correlation logic (route map join, linking, merging, labelling, prioritisation) is our own work.

| Tool | Role | Rulesets / config |
|---|---|---|
| Semgrep | SAST, taint mode for injection classes | `[TODO]` |
| Bandit | SAST, pattern checks such as hard-coded secrets | `[TODO]` |
| OWASP ZAP | DAST | `[TODO]` |

Versions: `[TODO]`

## 8. Metric targets

From the PRD. Good qualifies; Great stands out. No results measured yet.

| What we measure | Good | Great |
|---|---|---|
| Code detection | Over 60% | Over 85% |
| Runtime detection | Over 50% | Over 80% |
| Correct links (of 20 pairs) | Over 50% | Over 80% |
| Wrong links | Under 20% | Under 5% |
| False alarms (safe decoys) | Under 30% | Under 10% |
| Unseen app (pairs linked) | Over 40% | Over 65% |
| Run time | Under 15 minutes | Under 5 minutes |

Test app facts: 36 planted vulnerabilities (20 pairs, 10 code-only, 6 runtime-only), about 8 safe decoys, and an unseen second app at judging.
