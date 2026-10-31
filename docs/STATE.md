# STATE

Rules: one file, overwritten at each save, never a log. Maximum 150 lines. Nothing is marked passed unless it was run in this repo.

## 1. Last updated

2026-11-01. BS7 is on `feat/bs7-negative-evidence-ambiguity-coverage`. Waves A/B and Wave C are committed through `24f078e`. Full suite: 289 passed, 3 skipped. The first live run found four CWE-89 wrong suppressions; CWE-89 was removed, and the follow-up run had none.

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
- Q5: `no_http_path` reason codes `no_callers` and `walk_unresolved`. Only `no_callers` in injection CWEs can be suppressed. Off until measured. Q6: `blocked_by_validation` is a per-param outcome with sub-codes; status assigned in a fixed order.
- Q7: all AI is off by default and in judging mode. Q8: strict mode has no fallback for an unresolved receiver. Q9: config names live in one place.
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
| M2 core | `BS6` to `BS9` | in progress | `BS6` passed; `BS7` in progress; `BS8`-`BS9` not started |
| M3 extras | `BS10` | not started | None |

Current build stage: `BS7` is in progress on `feat/bs7-negative-evidence-ambiguity-coverage`. BS6 passed its live exit run. Details: section 9.

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
| `BS6` | `uv run --locked pytest -q`, `ruff check .` | 248 passed, ruff clean. New: command-injection oracle, boolean/timing SQL oracles, header/cookie checks, two-pass scheduler, correlation dedupe fix, auth-header wiring, sweep wiring. |
| `BS6` | `find_sinks` and offline pipeline plan on `.targets/VulnerableApp` | 2 CWE-78 sinks found: `CommandInjection.java` 48 and 53 (`new ProcessBuilder`), `dynamic`, matching `expectedIssues.csv` (CWE-77). CWE-89 unchanged. Plan: 17 directed jobs (78, 89), 167 sweep jobs (78/79/89/601). |
| `BS6` | **Live exit run:** `elenchus scan --source-path .targets/VulnerableApp --base-url http://127.0.0.1:9090/VulnerableApp --no-store`, sweep wired, ZAP 2.17.0 | exit 0, wall 3:37. 5 Confirmed CWE-89: ErrorBased LEVEL_1-4 on exact pair lines 83/143/206/272, and `AuthLoginService.java:51` as one issue (dedupe fix live, was 2). 18 Code-only, 2 Runtime-only headers (693, 1021). probe `stage_seconds` 216, 38 jobs attempted (36 finished, 1 all_blocked, 1 stopped_at_limit), 146 `skipped_budget`. attribution_rate 0.950, header_propagation 1.0, no foreign hosts. |
| `BS7` Wave A | `uv run --locked pytest -q tests/producers/test_sink_finder.py`; Ruff on changed files | 29 passed; Ruff clean. Static now prioritizes `safe_pattern` before `no_http_path`; commit `31624cc`. |
| `BS7` Waves B/C (`24f078e`) | Full `uv run --locked pytest -q`; Ruff; `git diff --check`; two live scans against local VulnerableApp/ZAP | 289 passed, 3 skipped. Follow-up: 36 jobs finished, 148 skipped; 5 Confirmed, 18 Code-only, 2 Runtime-only; 0/5 ambiguity; attribution_rate 0.954, header propagation 1.0, no foreign hosts. First run found 4 wrong CWE-89 suppressions; CWE-89 removed. Follow-up: 0 wrong suppressions; suppressed file empty. Expected-pairs YAML is absent, so recall and attribution accuracy are unavailable. |

Not run: the updated CI workflow on GitHub. The VulnerableApp benchmark with a complete expected-pairs file remains unavailable.

Older code still running on the new record with its older logic: tier correlation (reworked in `BS5`), alert-driven ZAP runner (`BS4`), `elenchus scan` (`BS5`), which still needs the Semgrep extra.

Pinned: ZAP and VulnerableApp images by digest in `infra/`. VulnerableApp source in `.targets/` at commit 9f45cd5. Its image is the `latest` digest on the same day, so line numbers may differ from the source.

Semgrep yardstick: `[TODO: Semgrep count on VulnerableApp with unfitted rules; record count, date and rule version in STATE.md]`

## 6. Not done, in dependency order

The build stages in `docs/implementation-plan.md` are the list. `BS0` to `BS6` have passed.

1. `BS7`: finish exit checks; decoy/twin live comparison and expected-pairs measurement remain incomplete
2. `BS8`: secrets, exports, measurement
3. `BS9`: judging mode and generality (M2 gate)
4. `BS10`: Should list (M3). 5. `BS11`: Could list

Other TODO marks: `grep -rn "TODO" docs AGENTS.md`.

## 7. Known failures and residual flaws

- Oracles: SQL error (89), XSS reflected `text/html` only (79), open redirect (601), command output (78) — all registered and in the coordinator's scan and replay path. `sql_boolean` (three-response) is built and unit-tested but not wired: it needs a true/false replay pair, verified on a blind-SQL route live. `timing_slower` is built and unit-tested but not registered: it needs `probe.timing_repeats` and a live timing baseline.
- Command injection and XSS/open-redirect are now probed dynamically by the sweep pass. Static catalogue: command injection added (ProcessBuilder/Runtime.exec). XSS (String.format reflected into ResponseEntity) and open redirect (location added to a header map) have no safe low-level API anchor without dataflow; left to catalogue-growth work, dynamic sweep covers them meanwhile.
- Header/cookie findings use `ORACLE` evidence with `oracle: header_check` and `header_name` in detail; no schema change. The VulnerableApp grader ignores them.
- Live run confirmed no CWE 78/79/601, expected not a regression: the command route returns ping output (oracle wants uid/gid), XSS routes reply `text/plain` (oracle wants `text/html`), open-redirect sweep routes not reached in budget. Confirm those oracles live on routes that suit them.
- Probe stage ran 216s against a 170s start-deadline: in-flight jobs (scan plus replays, `max_job_seconds` 30) finish past it. Total wall 3:37 under the 5-minute cap; tune budgets in BS8. A single ZAP timeout no longer aborts the run (wrapped in `ZapApi.call`; the job is recorded `errored`).
- Routes whose handler reads every param have no param name to seed (`XSSWithHtmlTagInjection`). The sweep still probes their declared params. Generated-name seeding not built.
- The answer key's line on a multi-line call is the argument's, not the call's. `BS3` and the command-injection catalogue follow it. Confirm at kickoff.
- BS7 live scan: four planted CWE-89 sinks were `tested_negative`; default suppression of CWE-89 was removed. Follow-up suppresses none. The complete decoy/twin live comparison and expected-pairs attribution accuracy remain unmeasured.
- ZAP sends one random-path request per job for 404 analysis: the one known request outside the route table.
- Same-route sink ambiguity. `TRACE` unavailable at judging; `RESPONSE_TRACE` helps only when a stack trace leaks. A third unfound sink can mislead a link.
- A negative result is not proof of safety; the state guard limits damage, not prevents it.
- Second-order bugs, IDOR, business logic have no oracle. Blind SSRF and XXE need callbacks. Recall depends on the catalogue; third-party wrappers are missed.
- `docs/decisions.md` stale. Superseded: D-04, D-05, D-06, D-07, D-08, D-14, D-16, D-17.

## 8. Open questions for the user

- Name of the environment variable for the base URL, the alternative to `--target`.
- Where the context path found by preflight is stored: `ScanTarget` or the preflight output.
- Path traversal: confirm the passwd line pattern.
- `oracle_flaky` sits inside the evidence entry. `conflict` is a boolean. Confirm.
- Header counting and multi-route export counting: confirm `header.count_mode` and `export.count_multi_entry` at kickoff against the answer key.
- Config values still TODO: `probe.timing_repeats`. Budget, back-guided and band values are proposed, to be tuned on runs.
- Does the organisers' app need a login? The `target.auth.*` header scheme is wired and off unless set.
- A safety classifier stopped a response twice in this session (before BS4; mid-BS6). No state lost.
- From the README: the organisers' app framework and Semgrep rule-set version for the offline yardstick.

## 9. Next action

Wave B implements suppression, coverage, and ADEQUACY evidence. Wave C implements deterministic primary ranking, replay conflict handling, flaky evidence, and response-trace resolution. Wave C is committed as `24f078e`. Full suite: 289 passed, 3 skipped; Ruff passed. The follow-up live scan removed wrong suppressions, but BS7 is not passed: decoy/twin live checks and expected-pairs accuracy remain. Next: finish those checks.

BS8 follow-up: tune probe budgets; the last live scan ran 216s against a 170s job-start deadline. Deferred BS6: live-check boolean/timing SQLi, command injection, XSS, and open redirect oracles. `target.auth.*` is wired but the app's login requirement is unknown.

## 10. Resume instructions

Read `AGENTS.md`, then this file, then `docs/implementation-plan.md`, then `docs/finding-schema.md` and `common/record.py`.
