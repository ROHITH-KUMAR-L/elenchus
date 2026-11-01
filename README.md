# elenchus — SAST + DAST Correlation

CyberForge hackathon entry. A Python CLI that scans a Java/Spring application's
**source code** (SAST) and its **running instance** (DAST), then **correlates**
the two so each real vulnerability appears once — with the code line that causes
it and the runtime proof that it is exploitable.

Full spec: [docs/prd.md](docs/prd.md). Design: [docs/architecture.md](docs/architecture.md). Current state: [docs/STATE.md](docs/STATE.md).

## Problem

Security teams run two kinds of scanners that never meet:

- **SAST** reads source code → "SQL injection at `orders.java:88`" but can't prove it is reachable.
- **DAST** attacks the running app → "SQL injection at `/api/orders?id=`" but can't say which code to fix.

The result is duplicate tickets, noisy false alarms, and no clear priority. The
challenge is to **link the runtime finding to the code that causes it**, merge
duplicates, and produce one prioritised list.

## How we solve it

**Static-guided dynamic testing with deterministic oracles.**

1. **Static analysis makes hypotheses.** An own tree-sitter code index + per-CWE
   YAML sink catalogue (anchored on low-level JDK/Spring APIs, never app names)
   finds sinks and walks the call graph back to the routes that reach them.
2. **ZAP probes, the project orchestrates.** OWASP ZAP's active scanner is the
   payload engine. Each probe carries a `hypothesis_id`, so a hit is **linked by
   lineage**, not matched afterward.
3. **Project oracles own the verdict.** Deterministic differential oracles
   (SQL error, command output, reflected XSS, open redirect, boolean-blind SQL)
   decide every verdict on a replayed response — a ZAP alert alone never does.
4. **Correlation + prioritisation.** Findings merge on `(sink_id, cwe)`; each
   issue is labelled Confirmed / Code-only / Runtime-only, scored, and ranked.

Safety: DAST targets `localhost` only, scoped to the route table; AI and Semgrep
are off by default and in judging mode; the whole run stays under 5 minutes.

### Methodology

```mermaid
flowchart LR
    SRC[Java source] --> IDX[Code index + sink catalogue]
    IDX --> HYP[Hypotheses: route, CWE, lineage id]
    HYP --> ZAP[ZAP probes + own replays]
    APP[Running app on localhost] --> ZAP
    ZAP --> ORC[Deterministic oracles]
    ORC --> COR[Correlate by lineage, merge on sink_id+cwe]
    COR --> OUT[Prioritised list: Confirmed / Code-only / Runtime-only]
```

### System architecture

```mermaid
flowchart TD
    CLI[elenchus CLI] --> P1[1-2 Adapter: routes + sinks]
    CLI --> P3[3 Hypotheses]
    P1 --> P3
    P3 --> P4[4 Probe coordinator]
    P4 <--> Z[(OWASP ZAP<br/>loopback API)]
    Z <--> T[(Target app<br/>localhost)]
    P4 --> P5[5 Correlate]
    P5 --> P6[6 Verify / confidence]
    P6 --> P7[7 Output: JSON / SARIF / report]
    P5 -.optional.-> DB[(Postgres)]
```

## Run

```bash
# infra: ZAP (loopback API) + the target app, via Docker Compose
docker compose -f infra/zap.compose.yaml up -d
docker compose -f infra/vulnerableapp.compose.yaml up -d

# one command; judging profile = ZAP on, AI/Semgrep off, <5 min
export ZAP_API_KEY=...            # from the ZAP service
uv run elenchus scan --judging \
  --source-path .targets/VulnerableApp \
  --base-url http://127.0.0.1:9090/VulnerableApp
```

Open-source components (correlation logic is our own): **OWASP ZAP** (active
scanning), **tree-sitter-java** (parsing), optional **Semgrep** (offline
cross-check only).

## Results

Measured locally on **OWASP VulnerableApp** (full scan, live OWASP ZAP). SAST
scores are against VulnerableApp's own `expectedIssues` export (a superset
spanning 30 CWE types); the organisers' answer key will differ. "Supported" =
the CWE classes the tool targets.

One scan: **61 findings across 11 CWE classes — 12 Confirmed, 36 Code-only,
13 Runtime-only, 0 wrong links.**

| PRD metric | Good / Great | Result |
|---|---|---|
| Code detection (SAST, supported CWEs) | >60% / >85% | **23/35 (66%)** — SQL 9/9, XSS 11/19, cmd 2/2 |
| Runtime detection (DAST) | >50% / >80% | SQL-89, XSS-79, cmd-78, open-redirect-601 all confirmed live |
| Correct links (planted pairs) | >50% / >80% | **12/20 (60%)** Confirmed: SQL-89 ×9, XSS-79 ×2, cmd-78 ×1 |
| Wrong links | <20% / <5% | **0** |
| Run time | <15m / <5m | `--judging` **< 5 min**; full report run ~12.7 min |
| Second framework (B-7) | bonus | servlet adapter runs on OWASP BenchmarkJava (SAST): 5480 routes, 1806 sinks |

Probe health on that run: attribution 0.952, header propagation 1.000, no state
drift, no foreign hosts.

Honest gaps (details in [docs/STATE.md](docs/STATE.md)): static XSS catches the
unescaped sinks but not escaped-yet-bypassable ones; XSS on handlers that bind
every parameter (`Map<String,String>`) stays Code-only; open redirect is
confirmed dynamically but has no safe general static anchor on this app;
without the flow engine, precision on a hold-out like BenchmarkJava is
discrimination-limited (high recall, high false-positive rate).
