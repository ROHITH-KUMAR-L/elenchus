# Implementation plan

Status: plan. Nothing is built or measured. Hackathon length and team size: `[TODO: confirm at kickoff]`

## Phases

| Phase | Work | Unblocks |
|---|---|---|
| 0. Pre-kickoff | Run VulnerableApp on localhost. Read its `benchmarks/README.md`. Fill the vocabulary table in [finding-schema.md](finding-schema.md). Self-benchmark SAST and DAST separately against `POST /VulnerableApp/scanner/benchmark`. | Vocabulary, early recall numbers |
| 1. Hour one | Ratify and freeze the internal finding record and its SARIF mapping. Fix the adapter interface. Ratify network, volume and service names. | Everything |
| 1b. Our infra | Stand up `sastdast-postgres` on `sastdast-net` with volume `sastdast-pgdata` [proposed names]. Separate from the target's network. Resolve CLI/ZAP placement first. | Run store for phase 5 dedupe |
| 2. Easy points | Secrets/crypto pass (Code-only). ZAP passive scan (Runtime-only headers). | 16 of 36 bugs, no correlation needed |
| 3. Spring MVC adapter | Route map: annotations, base paths, dynamic segments, params. Semgrep taint rules with full `taint_trace`. Semgrep SARIF ingest. | Correlation, ZAP seeding |
| 4. DAST + oracles | ZAP active scan seeded from the route map. Oracles for the four types. | Confirmed labels |
| 5. Correlation | Tiers A, B, C. Labels. Merge on `(cwe, file, line)` against issues in the run store. Risk score. | Report, link metrics |
| 6. Report | Prioritised CLI output with FR-8 issue detail. README run steps. | Demo |
| 7. Harden + measure | Run on the organisers' app. Measure links against the 20 pairs. Fix wrong links. | Scoring |
| 8. Secondary + bonus | JAX-RS adapter. AI helpers B-4, B-3. Then B-2, B-6 (SARIF export + CI exit code), B-5 (scan comparison from the run store). | Bonus points |

D-07 is resolved: Tier B uses call edges (`reached_via`). Phase 3's route-map parser must emit one-hop call edges. See [decisions.md](decisions.md).

## Dependency order

```mermaid
flowchart LR
    contract["Internal record + SARIF mapping + adapter interface"]
    contract --> secrets[Secrets/crypto pass]
    contract --> passive[ZAP passive]
    contract --> rmap[Route map]
    rmap --> active[ZAP active seeding]
    rmap --> oracles[Oracles]
    contract --> semgrep["Semgrep taint + trace (SARIF in)"]
    contract --> store["Run store (Postgres)"]
    secrets & passive & active & oracles & semgrep & store --> corr[Correlation]
    corr --> report[Report] --> sarif[SARIF out]
```

## Parallel tracks (small team)

| Track | Owns | Starts after |
|---|---|---|
| SAST | Semgrep taint rules, trace output, secrets/crypto pass | Schema frozen |
| Route map | Spring MVC parser, then JAX-RS | Schema frozen |
| DAST | ZAP driver, seeding, oracles | Schema frozen. Seeding waits on route map. |
| Correlation | Tiers, merge, scoring, report, link measurement | Schema frozen. Works on hand-written fixtures until real findings exist. |
| Infra | Postgres network, volume and service; run store; SARIF export | Names ratified. Store must exist before phase 5 merge. |

Owners: `[TODO: team names]`

## Cut list (drop in this order if short on time)

1. Fuzzy correlation fallback and taint-spec inference
2. B-1 auto-verify
3. JAX-RS adapter
4. Nuclei
5. B-6 SARIF export
6. B-5 scan comparison
7. Path traversal (CWE-22)
8. B-2 false-positive triage

Never cut: internal record, Semgrep SARIF ingest, run store (FR-6 re-run dedupe), Spring adapter, Tier B, param guard, oracles, CLI report.

## Metric targets

From the PRD. No results recorded.

| What we measure | Good | Great |
|---|---|---|
| Code detection | >60% | >85% |
| Runtime detection | >50% | >80% |
| Correct links (of 20 pairs) | >50% | >80% |
| Wrong links | <20% | <5% |
| False alarms | <30% | <10% |
| Unseen app (pairs linked) | >40% | >65% |
| Run time | <15 min | <5 min |

VulnerableApp's grader measures detection only. Link metrics are measured by us against the planted pairs.
