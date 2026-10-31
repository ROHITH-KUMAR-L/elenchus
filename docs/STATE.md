# STATE

Rules: one file, overwritten at each save, never a log. Maximum 150 lines. Nothing is marked passed unless it was run in this repo.

## 1. Last updated

2026-11-01. Trigger: `BS0` to `BS5` passed and pushed to `main`; M1 cleared. Local ZAP and VulnerableApp containers run from `infra/`.

## 2. Architecture

Static-guided dynamic testing. Static analysis makes hypotheses. OWASP ZAP performs active probes; project orchestration keeps hypothesis context and deterministic oracles own verdicts.

- Pipeline stages: 0 preflight, 1 code index, 2 static, 3 hypotheses, 4 ZAP-backed probe orchestration, 5 correlation, 6 verify, 7 output.
- Build stages: `BS0` onward. The order we build it in. Milestones are gates over them.
- Stage 2 is the own sink finder and secrets/crypto pass. Semgrep is an optional adapter, off by default.
- One ZAP job per `(route, method)`, one at a time. Param from a request diff, CWE from the rule ID, verdict from a coordinator replay. Built in `BS4`, wired end to end in `BS5`.
- A firing probe proves route, param and CWE. It does not prove which sink on that route is the cause.
- Residual risk is same-route sink ambiguity, marked with `link_status: ambiguous`.
- Detail: `docs/architecture.md`. Contract: `docs/finding-schema.md`. Build stages: `docs/implementation-plan.md`. Repo map: `docs/repo-structure.md`.

## 3. Decisions locked

Config names and default values live in the Config reference in `docs/architecture.md`. This list does not repeat values.

- D1: back-guided search is Should, relaxed mode only, off until measured. Entry `run_back_guided`.
- D2: a positive oracle versus a `tested_negative` sink is replayed (`replay.count`, `replay.min_hits`). Enough hits un-suppress it.
- D3: `link_status` and `link_origin` are both required and orthogonal.
- D4: build stages set the order. The own flow engine is Should, after M2.
- D5: contract fields `match_mode`, `unresolved_hops`, `candidate_sinks`, `conflict`, `oracle_flaky`.
- R1: the adequacy logic and a suppressed file with real content are M2.
- R2: stage 3 emits one Hypothesis record type for the directed and sweep sets.
- R3: work is split by build stage, not by person. The module boundary between static code and probe or engine code stays. Proposed directories `probe/` and `producers/hypotheses/`. Neither exists.
- R4: alternative sinks go in the SAST grader payload. In the report they are attributes of the primary issue.
- R5: the flow-engine gate is a new Semgrep count with unfitted rules. The old figure overstates.
- R6: `match_mode` defaults to `strict`. A conflict case is Confirmed at or above the confirm threshold. Below it, it is Runtime-only with the sink in `candidate_sinks`, and it is not suppressed.
- R7: ZAP is the active probe engine, including judging mode. Project code owns orchestration, provenance, oracles and findings. AI never creates or deletes a finding, sets a verdict or decides a link.
- F4: fallback dedupe keys. Secrets `(cwe, file, line)`. Runtime-only injection `(cwe, normalised_route, method, param)`. Headers `(cwe, header_name)`, per `header.count_mode`.
- G1 to G4: confidence is a float from 0 to 1 with three bands in config. `confidence_reasons` is a list of `{factor, delta}`, written by the engine only.
- Q1: JAX-RS stays Could. B-5 is Should, M3.
- Q2: path traversal is Should, M3, the first item after M2.
- Q3: `handler_*` leave the record. `call_chain` items are `{method, file, line}`.
- Q4: the base URL is a required input (`--target`). The context path is detected and never guessed silently.
- Q5: `no_http_path` reason codes `no_callers` and `walk_unresolved`. Only `no_callers` in injection CWEs can be suppressed. Off until measured.
- Q6: `blocked_by_validation` is a per-param outcome with sub-codes. Status is assigned in a fixed order.
- Q7: all AI is off by default and in judging mode.
- Q8: strict mode has no fallback for an unresolved receiver.
- Q9: config names live in one place.
- S1 attribution: request diff plus rule ID, not alerts. Candidate hits are replayed by the coordinator. Canary is added at replay.
- S2 budget: a deadline scheduler, directed pass then sweep. Reserved replay budget. `probe.max_jobs` is only a safety limit.
- S3 decoys: `arg_shape` gives `safe_pattern`. Stricter adequacy test. `wrong_suppression_count` gates `export.suppress_cwes`. Decoys have vulnerable twins.
- S4 state: risk ordering, drift check, stop on drift. No read-only rule, no reset.
- S5 safety: allow-list policy, exact-route scope, no redirects on replay, run-end host check.
- S6 catalogue: entries have a `kind`, including non-call sinks. Anchored on low-level APIs.
- S7 ambiguity: `RESPONSE_TRACE` from replay stack traces, behind the adapter.
- S8 auth: optional `target.auth.*`. Session manager moves up only if kickoff shows a login.
- S9 reporting: supported-CWE and raw scores side by side. Per-CWE recall with tagged misses. Attribution rate and accuracy.
- S10 generality: CI ban on test-app names, catalogue freeze, rehearsal with minimal inputs. Hold-out repos are static only.

## 4. Milestone status

| Milestone | Build stages | Status | Evidence |
|---|---|---|---|
| M1 spine | `BS0` to `BS5` | PASSED | M1 gate cleared on 2026-11-01. Exit tests below. |
| M2 core | `BS6` to `BS9` | not started | None |
| M3 extras | `BS10` | not started | None |

Current build stage: `BS6`, partly done. Offline work only. Not wired into the coordinator or pipeline. Not live-tested. Details: section 9.

## 5. Done

| Build stage | Exit test run | Result |
|---|---|---|
| `BS0` | `scripts/bs0_zap_check.py` against pinned ZAP 2.17.0 and VulnerableApp, 16 jobs. Output in `out/bs0/results.json`, not tracked. | All eight checks have a result and a decision. See `docs/architecture.md#zap-acceptance-check`. |
| `BS1` | `uv run --locked pytest -q` with Semgrep uninstalled | 137 passed, 3 skipped (they need Semgrep) |
| `BS1` | `uv run --locked --extra semgrep pytest -q tests/producers/test_semgrep_runner.py` | 7 passed |
| `BS1` | `uv run --locked ruff check .` | Passed |
| `BS1` | `docker build -f cli/Dockerfile`, then `--help` in the container | Built. Runs as uid 10001. No Semgrep in the image. |
| `BS2` | `python -m producers.sast.code_index .targets/VulnerableApp` | 220 route entries: 167 GET, 51 POST, 2 ANY. 277 params. `params_status`: 146 complete, 52 partial, 22 unknown. 4052 call edges, 1201 into source, 475 unresolved. |
| `BS2` | Index against the app's live `/scanner` list | All 159 live route and method pairs are in the index. 60 indexed pairs are not in that list. |
| `BS3` | Own sink finder on `.targets/VulnerableApp`, compared with its `expectedIssues.csv` | CWE-89: all 9 expected sinks found on the exact line. All 9 are `dynamic`. Other CWEs not built yet. |
| `BS3` | Hypotheses on the same source | 11 directed, 239 sweep, 13 params skipped by type. Every `expected_pairs` entry has a directed hypothesis. |
| `BS3` | `uv run --locked pytest -q`, `ruff check .` | 178 passed, 3 skipped. Ruff passed. |
| `BS4` | `uv run --locked pytest -q tests/probe` | 38 passed: attribution (missing header, zero/two-param diffs unlinked), oracle, seeds, preflight, coordinator (reproduced hit links, non-reproducing makes no record, foreign host reported). |
| `BS4` | `scripts/bs4_live_check.py` against live ZAP and VulnerableApp | 11 directed SQL jobs ran. 4 Confirmed error-based SQL findings (ErrorBased LEVEL_1 to LEVEL_4), each fired 3/3 on replay with unique lineage. attribution_rate 0.965, header_propagation_rate 1.0, no foreign hosts. Context path /VulnerableApp from config. |
| `BS4` | `uv run --locked pytest -q`, `ruff check .` | 216 passed, 3 skipped. Ruff passed. |
| `BS5` | `uv run --locked pytest -q` | 214 passed, 3 skipped (the drop from 216 is the old scan-wiring and tier tests replaced by lineage tests). Ruff passed. |
| `BS5` | **M1 gate:** `uv run --locked elenchus scan --source-path .targets/VulnerableApp --base-url http://127.0.0.1:9090/VulnerableApp --no-store` | One command, live ZAP. 21 issues: 4 Confirmed error-based SQL (ErrorBased LEVEL_1 to LEVEL_4), all link_status unique, confidence 0.95, each matching expected_pairs on exact file and line; 17 Code-only; 0 Runtime-only. attribution_accuracy 4/4 = 1.0. |

Not run: the updated CI workflow on GitHub. No correlation, probe or benchmark results exist.

Older code still running on the new record with its older logic: tier correlation (reworked in `BS5`), alert-driven ZAP runner (`BS4`), `elenchus scan` (`BS5`), which still needs the Semgrep extra.

Pinned: ZAP and VulnerableApp images by digest in `infra/`. VulnerableApp source in `.targets/` at commit 9f45cd5. Its image is the `latest` digest on the same day, so line numbers may differ from the source. Confirm when `expected_pairs` is checked live.

Measured: nothing beyond `BS0`. Semgrep yardstick: `[TODO: Semgrep count on VulnerableApp with unfitted rules; record count, date and rule version in STATE.md]`

## 6. Not done, in dependency order

The build stages in `docs/implementation-plan.md` are the list. `BS0` to `BS3` have passed.

1. `BS6`: all classes and the scheduler
2. `BS7`: negative evidence, ambiguity, coverage
3. `BS8`: secrets, exports, measurement
4. `BS9`: judging mode and generality (M2 gate)
5. `BS10`: Should list (M3)
6. `BS11`: Could list

Other TODO marks live in the docs. List them with `grep -rn "TODO" docs AGENTS.md`.

## 7. Known failures and residual flaws

- Oracles built offline: SQL error, XSS (`text/html` only), open redirect, boolean SQL. Not wired live. Command injection and timing SQL: not built.
- Routes whose handler reads every param have no param name to seed. `XSSWithHtmlTagInjection` is one. Decide in `BS6`.
- The answer key's line on a multi-line call is the argument's, not the call's. `BS3` follows it. Confirm with the organisers' key at kickoff.
- Two safe VulnerableApp SQL sinks stay `dynamic` because their input is filtered before the call. They need a probe to clear them. One unreachable config sink is `dynamic` with `no_callers`, so it would report as Code-only.
- ZAP sends one random-path request per job for its 404 analysis. It is the one known request outside the route table.
- `BS0` jobs took under 2 seconds, on a few routes only. No full scan has run. VulnerableApp lists 171 routes.
- Same-route sink ambiguity. `TRACE` is unavailable at judging. `RESPONSE_TRACE` helps only when a stack trace leaks.
- A third sink that was never found can give a misleading link.
- A negative result is not proof of safety. The state guard limits damage and does not prevent it.
- Second-order bugs and multi-step workflows are not covered in M1 or M2. IDOR and business logic have no oracle. Blind SSRF and XXE need callbacks.
- Recall depends on the sink catalogue. Third-party wrappers are missed.
- `docs/decisions.md` remains stale. Superseded there: D-04, D-05, D-06, D-07, D-08, D-14, D-16, D-17.

## 8. Open questions for the user

- Name of the environment variable for the base URL, the alternative to `--target`.
- Where the context path found by preflight is stored: `ScanTarget` or the preflight output.
- Path traversal: confirm the passwd line pattern.
- `oracle_flaky` sits inside the evidence entry. `conflict` is a boolean. Confirm.
- Header counting and multi-route export counting: confirm `header.count_mode` and `export.count_multi_entry` at kickoff against the answer key.
- Config values still TODO: `probe.timing_repeats`. Budget, back-guided and band values are proposed, to be tuned on runs.
- Does the organisers' app need a login? Decides whether the session manager moves to `BS6`.
- `BS4`: a safety classifier stopped an earlier response in this session, before `BS4` began. Decide whether to continue it here.
- From the README: the organisers' app framework (kickoff) and Semgrep rule-set version for the offline yardstick.
- From the stale `docs/decisions.md` (D-12): which VulnerableApp module stands in for the code-only path, crypto or JWT.

## 9. Next action

1. Live check first, once ZAP and VulnerableApp are up (`infra/`, Docker). Re-run `elenchus scan` against VulnerableApp. The earlier BS4 and BS5 results used the replay bug and count for nothing until re-run.
2. Wire `run_two_pass` into the coordinator run loop, with `probe.stage_budget_seconds.zap_jobs` as the budget.
3. Wire the header checks (`probe/headers.py`) into the baseline pass, as runtime-only findings.
4. Wire `sql_boolean` into the coordinator as a true and false replay pair per candidate.
5. Catalogue kinds `return_value`, `annotation`, `template`, `xml` in `sink_finder.py`, then XSS and redirect entries. Check offline against `expectedIssues.csv`.
6. Decide the `target.auth.*` scheme with the user. Credentials from environment variables only.
7. Command-injection oracle: needs a verified timing signal from ZAP, checked live.

## 10. Resume instructions

Read `AGENTS.md`, then this file, then `docs/implementation-plan.md`, then `docs/finding-schema.md` and `common/record.py`.
