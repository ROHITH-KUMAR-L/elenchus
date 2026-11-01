# STATE

## 1. Last updated

2026-11-01. M1 and M2 cleared. `BS10a`-`d` done. `BS10e`-`j` done (all of the M3 Should list): scan comparison (B-5), session manager, passive ingestion, preflight extras, AI with/without harness + client, advisory AI (fix text, link explanations, DTO seeds). See Done table. 358 tests pass, 3 skipped, ruff clean. All AI off by default and in judging. Local ZAP and VulnerableApp run from `infra/`.

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
- D4: build stages set the order; the own flow engine is Should, after M2. D5: contract fields `match_mode`, `unresolved_hops`, `candidate_sinks`, `conflict`, `oracle_flaky`.
- R1: the adequacy logic and a suppressed file with real content are M2.
- R2: stage 3 emits one Hypothesis record type for the directed and sweep sets.
- R3: work is split by build stage, not by person. The module boundary between static code and probe or engine code stays. Proposed directories `probe/` and `producers/hypotheses/`. Neither exists.
- R4: alternative sinks go in the SAST grader payload. In the report they are attributes of the primary issue.
- R5: the flow-engine gate is a new Semgrep count with unfitted rules. The old figure overstates.
- R6: `match_mode` defaults to `strict`. A conflict case is Confirmed at or above the confirm threshold. Below it, it is Runtime-only with the sink in `candidate_sinks`, and it is not suppressed.
- R7: ZAP is the active probe engine, including judging mode. Project code owns orchestration, provenance, oracles and findings. AI never creates or deletes a finding, sets a verdict or decides a link.
- F4: fallback dedupe keys. Secrets `(cwe, file, line)`. Runtime-only injection `(cwe, normalised_route, method, param)`. Headers `(cwe, header_name)`, per `header.count_mode`.
- G1 to G4: confidence is a float from 0 to 1 with three bands in config. `confidence_reasons` is a list of `{factor, delta}`, written by the engine only.
- Q1: JAX-RS stays Could; B-5 is Should, M3. Q2: path traversal is Should, M3, first after M2.
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
| M2 core | `BS6` to `BS9` | PASSED | M2 gate cleared 2026-11-01 (judging rehearsal, 3:35). Exit tests below. |
| M3 extras | `BS10` | not started | None |

Current build stage: `BS10` Should list complete (`BS10a`-`j`). Gaps to close (section 9), then `BS11` Could list.

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
| `BS4` | `uv run --locked pytest -q`, `ruff check .`; live BS4 check (harness since superseded by `elenchus scan`) | 216 passed, 3 skipped, ruff clean. Live: 4 Confirmed error-based SQL (ErrorBased LEVEL_1-4), each 3/3 on replay, unique lineage, attribution_rate 0.965, no foreign hosts. |
| `BS5` | `uv run --locked pytest -q` | 214 passed, 3 skipped (the drop from 216 is the old scan-wiring and tier tests replaced by lineage tests). Ruff passed. |
| `BS5` | **M1 gate:** `uv run --locked elenchus scan --source-path .targets/VulnerableApp --base-url http://127.0.0.1:9090/VulnerableApp --no-store` | One command, live ZAP. 21 issues: 4 Confirmed error-based SQL (ErrorBased LEVEL_1 to LEVEL_4), all link_status unique, confidence 0.95, each matching expected_pairs on exact file and line; 17 Code-only; 0 Runtime-only. attribution_accuracy 4/4 = 1.0. |
| `BS6` | `uv run --locked pytest -q`, `ruff check .` | 248 passed, ruff clean. New: command-injection oracle, boolean/timing SQL oracles, header/cookie checks, two-pass scheduler, correlation dedupe fix, auth-header wiring, sweep wiring. |
| `BS6` | `find_sinks` and offline pipeline plan on `.targets/VulnerableApp` | 2 CWE-78 sinks found: `CommandInjection.java` 48 and 53 (`new ProcessBuilder`), `dynamic`, matching `expectedIssues.csv` (CWE-77). CWE-89 unchanged. Plan: 17 directed jobs (78, 89), 167 sweep jobs (78/79/89/601). |
| `BS6` | **Live exit run:** `elenchus scan --source-path .targets/VulnerableApp --base-url http://127.0.0.1:9090/VulnerableApp --no-store`, sweep wired, ZAP 2.17.0 | exit 0, wall 3:37. 5 Confirmed CWE-89: ErrorBased LEVEL_1-4 on exact pair lines 83/143/206/272, and `AuthLoginService.java:51` as one issue (dedupe fix live, was 2). 18 Code-only, 2 Runtime-only headers (693, 1021). probe `stage_seconds` 216, 38 jobs attempted (36 finished, 1 all_blocked, 1 stopped_at_limit), 146 `skipped_budget`. attribution_rate 0.950, header_propagation 1.0, no foreign hosts. |
| `BS7` | `uv run --locked pytest -q`, `uv run --locked ruff check .` | 292 passed, ruff clean. Commit `ac42054` had deleted the conflict (x3) and response-trace (x3) fixtures and every test exercising the conflict rule, response-trace frame parser, `oracle_flaky` and the ambiguity primary rule; restored from `ac42054^` (commit `4cf1685`), they pass unchanged, so the Wave-C logic is proven. Decoy static layer (`safe_pattern` vs dynamic twins, `no_http_path` reasons), adequacy->`tested_negative`, `type_rejected`, and a non-empty `suppressed.json` are all covered in CI. |
| `BS7` | **Live exit run:** `elenchus scan ... --no-store --expected-pairs common/fixtures/expected_pairs/vulnerableapp.yaml`, ZAP 2.17.0 | exit 0, wall ~3:40. recall CWE-89 9/9 = 1.0, attribution_rate 0.950, attribution_accuracy 1.0 (8/8). `wrong_suppression_count` CWE-89 = 4 (the union/blind pairs marked `tested_negative`), so 89 stays out of `export.suppress_cwes`. 5 Confirmed CWE-89 (ErrorBased LEVEL_1-4 + `AuthLoginService.java:51`), 18 Code-only, 2 Runtime-only headers. 0 ambiguous, 0 suppressed, 0 flaky, no RESPONSE_TRACE: VulnerableApp has no same-route ambiguity or suppressible `safe_pattern` SQL, so those paths are proven by the CI fixtures, not live. probe `stage_seconds` 220. |

| `BS8` | `uv run --locked pytest -q`, `ruff check .` | 301 passed, ruff clean. New: own secrets/weak-crypto pass (CWE-798/327/330, `secrets.yaml`) emitting Code-only findings; `benchmark` rescored against our own producers with raw+supported; `ambiguity` and `wrong_suppression_count` added to coverage; SARIF verified. |
| `BS8` | **Measurement baseline** (`python -m producers.benchmark sast` + live `elenchus scan ... --expected-pairs`) | Benchmark over the full 105-row CSV: supported 11/22 (50%), raw 11/105 (10%); CWE-89 9/9, CWE-77 2/2, CWE-327 0/5 and CWE-330 0/6 (VulnerableApp hides weak crypto behind custom wrappers; our pass anchors on JDK APIs) — baseline, no target required. Live coverage (expected_pairs = CWE-89): recall 9/9, attribution_rate 0.953, accuracy 1.0, ambiguity 0/5 = 0.0, `wrong_suppression_count` CWE-89 = 4, header_propagation 1.0, probe stage 170s. Export defaults kept: `include_alternatives` on, `suppress_no_http_path` off (measured impact = 1 `no_callers` CWE-89 sink). |

| `BS9` | `uv run --locked pytest -q`, `ruff check .` | 307 passed, ruff clean. New: state guard (risk-ordered jobs, GET-sample drift detection, stop state-changing jobs on drift → `skipped_drift`, `drift_detected`); `--judging` + `ELENCHUS_BASE_URL`; generality CI test (bans the app package in detection code/config, app names in detection YAML); catalogue freeze (`catalogue/freeze.json`). Forced-drift unit test passes. |
| `BS9` | **M2 gate:** `elenchus scan --judging --source-path .targets/VulnerableApp --base-url http://127.0.0.1:9090/VulnerableApp --no-store` | exit 0, wall 3:35 (<5 min). One command, judging profile (AI+Semgrep off, ZAP on, no restarts), context path detected. 5 Confirmed CWE-89, attribution 0.952, no foreign hosts, drift_detected False. Generality CI green. Static-only hold-out run not done (no hold-out repo provisioned). |

| `BS10a-d` | **Live run:** `elenchus scan ... --expected-pairs`, ZAP 2.17.0, 317 tests pass | exit 0, wall 3:41. **9 Confirmed CWE-89** (ErrorBased LEVEL_1-4, Blind LEVEL_1-2 and Union LEVEL_1-2 via `sql_boolean`, AuthLoginService.java:51), all confidence 0.95. recall CWE-89 9/9, `wrong_suppression_count` CWE-89 = 0 (union/blind now Confirmed, not tested_negative), so 89 returned to `export.suppress_cwes`. ambiguity 0/9, attribution 0.957, no foreign hosts, no drift. probe stage 221s. Path-traversal oracle built+unit-tested but not Confirmed live (route not reached in budget / no passwd content elicited). back-guided and flow engine off by default, no effect on this run. |
| `BS10e` | `uv run --locked pytest -q tests/engine/test_compare.py tests/cli/test_main.py` | 50 passed. Pure `compare_runs` + `PostgresStore.read_run_issues` + `compare` CLI. Fixture `common/fixtures/scans/scan-compare.json` has a fixed, a new and a still-open issue; suppressed issues excluded from both sides. Not run against a live Postgres this stage. |
| `BS10f` | `uv run --locked pytest -q tests/probe/test_session.py` | 11 passed. `resolve_session` logs in once (cookie/json/header token), wired into the coordinator before scanning, overriding the static header. Integration test: a cookie-gated route is `all_blocked` without the login flow and `finished` with it. Login body read from env, not config; login URL localhost-only. Not run against a live auth app. |
| `BS10g` | `uv run --locked pytest -q tests/probe/test_passive.py` | 4 passed. `probe/passive.ingest` keeps ZAP passive alerts, drops our active-scanner plugins, dedups. Coordinator collects them best-effort (`ProbeResult.advisory_alerts`), CLI writes `advisory.json`. Test proves findings are byte-identical with and without alerts present: verdicts unchanged. Not run against a live ZAP this stage. |
| `BS10h` | `uv run --locked pytest -q tests/probe/test_preflight.py` | 14 passed. `preflight.probe_extras` reads the `Server` banner and an error-page fingerprint (framework markers or `<title>`) from a random missing path; skips cleanly when the target is down. Wired in the CLI pipeline, written to `advisory.json`. Advisory only. Not run live. |
| `BS10i` | `uv run --locked pytest -q tests/ai` | `ai/`: OpenAI-compatible `AiClient` (off by default and in judging, no call without credentials, content-hash cache, `ai.max_calls` budget, JSON-schema validation drops bad output) + `with_without` harness measuring correct/wrong links. Harness runs fully offline with AI off and emits a diff table. Transport injectable; no network in tests. No live AI call made. |
| `BS10j` | `uv run --locked pytest -q tests/ai` | 22 passed (whole `tests/ai`). Advisory AI: `ai/advisor.annotate` attaches fix text (B-4) and link explanations (B-3) to `Issue.ai_notes` only — a test asserts the issue is byte-identical apart from `ai_notes`. `ai/seeds.propose_seed` proposes DTO field values with up to 3 repairs. Wired into the CLI (`_apply_ai_advice`) and the text report; no-op when AI off. Integration test: a with/without run over real correlation shows 0 link regression. No live AI call made. |

Not run: the updated CI workflow on GitHub.

Pinned: ZAP and VulnerableApp images by digest in `infra/`. VulnerableApp source in `.targets/` at commit 9f45cd5. Its image is the `latest` digest on the same day, so line numbers may differ from the source.

Semgrep yardstick (recorded 2026-11-01): Semgrep 1.183.0, public pack `p/java` as shipped (no edits), over `.targets/VulnerableApp/src/main/java` (commit 9f45cd5). 34 findings across 8 rules; SQL injection = 12 (`tainted-sql-string` 10, `spring-sqli` 2). Also `tainted-html-string` 12, `tainted-url-host` 5, `tainted-file-path` 2, crypto 2, XXE 1. Our own sink finder finds 9 CWE-89 expected sinks (all Confirmed). `flow.enabled` stays off: the gate now has a number to compare a future flow-engine count against; flipping it is a BS11 measurement, not done.

## 6. Not done, in dependency order

`BS0`-`BS9` passed (M1, M2). `BS10` complete. Next: close the gaps (section 9), then `BS11` Could list. Other TODO marks: `grep -rn "TODO" docs AGENTS.md`.

## 7. Known failures and residual flaws

- Oracles: SQL error (89), XSS reflected `text/html` only (79), open redirect (601), command output (78) in ORACLES; `sql_boolean` and `timing_slower` wired through the coordinator's own confirmation passes. `timing_slower` stays gated on `probe.timing_repeats` (default off): wired and unit-tested (fake clock), but enabling needs a measured repeat count and a live timing baseline. It cannot be confirmed on VulnerableApp (blind/union SQL already Confirmed by `sql_boolean`).
- Command injection and XSS/open-redirect are now probed dynamically by the sweep pass. Static catalogue: command injection added (ProcessBuilder/Runtime.exec). XSS (String.format reflected into ResponseEntity) and open redirect (location added to a header map) have no safe low-level API anchor without dataflow; left to catalogue-growth work, dynamic sweep covers them meanwhile.
- Header/cookie findings use `ORACLE` evidence with `oracle: header_check` and `header_name` in detail; no schema change. The VulnerableApp grader ignores them.
- Live run confirmed no CWE 78/79/601, expected not a regression: the command route returns ping output (oracle wants uid/gid), XSS routes reply `text/plain` (oracle wants `text/html`), open-redirect sweep routes not reached in budget. Confirm those oracles live on routes that suit them.
- CWE-22 is not confirmable on VulnerableApp (investigated 2026-11-01): `PathTraversalVulnerability.readFile` uses `getResourceAsStream`, reading only classpath resources, so `/PathTraversal/LEVEL_1?fileName=../../../../etc/passwd` returns `{"content":null}` and no OS file content ever appears. ZAP's rule 6 and our file-content oracle both inject OS paths, so neither fires; the only "win" is reading a sibling classpath resource (`secret.json`), an app-specific name the generality rule forbids hardcoding. The oracle is unit-tested and correct for real filesystem sinks; it now also detects Windows ini files and leaked private keys.
- Probe stage ran 216s against a 170s start-deadline: in-flight jobs (scan plus replays, `max_job_seconds` 30) finish past it. Total wall 3:37 under the 5-minute cap; tune budgets in BS8. A single ZAP timeout no longer aborts the run (wrapped in `ZapApi.call`; the job is recorded `errored`).
- Routes whose handler reads every param have no param name to seed (`XSSWithHtmlTagInjection`). The sweep still probes their declared params. Generated-name seeding not built.
- The answer key's line on a multi-line call is the argument's, not the call's. `BS3` and the command-injection catalogue follow it. Confirm at kickoff.
- Adequacy marks union-based and blind SQLi sinks `tested_negative`: ZAP's CWE-89 rules run and get past validation, but the only confirming oracle is error-based (`sql_error`), so nothing fires. `coverage.py` now computes `wrong_suppression_count`; live CWE-89 = 4 (the union/blind `expected_pairs` sinks), so 89 stays out of `export.suppress_cwes` per the measurement rule and they stay visible as Code-only, not suppressed. The real fix is a union/blind oracle (`sql_boolean` is built, not yet wired) — carried to BS9. Conflict/ambiguity/response-trace behaviour is proven by the restored CI fixtures, not the live scan (VulnerableApp has none naturally).
- Secrets/crypto pass anchors on JDK APIs (MessageDigest/Cipher/Random/Math.random, secret-named literals); recall on VulnerableApp crypto is 0 because the app wraps weakness in its own utils. Recorded baseline, not fitted away.
- ZAP sends one random-path request per job for 404 analysis: the one known request outside the route table.
- Same-route sink ambiguity. `TRACE` unavailable at judging; `RESPONSE_TRACE` helps only when a stack trace leaks. A third unfound sink can mislead a link.
- A negative result is not proof of safety; the state guard limits damage, not prevents it. Second-order bugs, IDOR, business logic have no oracle; blind SSRF and XXE need callbacks; recall depends on the catalogue.
- `docs/decisions.md` stale. Superseded: D-04, D-05, D-06, D-07, D-08, D-14, D-16, D-17.

## 8. Open questions for the user

- Name of the environment variable for the base URL, the alternative to `--target`.
- Where the context path found by preflight is stored: `ScanTarget` or the preflight output.
- `oracle_flaky` sits inside the evidence entry. `conflict` is a boolean. Confirm.
- Header counting and multi-route export counting: confirm `header.count_mode` and `export.count_multi_entry` at kickoff against the answer key.
- Config values still TODO: `probe.timing_repeats`. Budget, back-guided and band values are proposed, to be tuned on runs.
- Does the organisers' app need a login? The `target.auth.*` header scheme is wired and off unless set.
- A safety classifier stopped a response twice in this session (before BS4; mid-BS6). No state lost.
- From the README: the organisers' app framework and Semgrep rule-set version for the offline yardstick.

## 9. Next action

`BS10` Should list complete (`BS10a`-`j`). Carried gaps addressed this session:
1. CWE-22: investigated — unconfirmable on VulnerableApp (classpath-resource reader; see §7). Oracle generalised (adds Windows ini, private keys) and unit-tested. Closed as a target property.
2. `timing_slower`: wired into the coordinator (`_confirm_timing`), gated on `probe.timing_repeats`, unit-tested with a fake clock. Off by default; a live timing baseline is still unrecorded (not exercisable on VulnerableApp).
3. Semgrep yardstick recorded (above): 12 SQL-injection findings. `flow.enabled` stays off; flipping it is a BS11 measurement.

Still needing live runs (next): `compare` against a live Postgres; session manager against an auth app; passive ingestion + preflight extras surfaced in a live ZAP run; an AI with/without run on VulnerableApp before any task goes default-on. Then `BS11` (Could list). M2 margin ~80s.

## 10. Resume instructions

Read `AGENTS.md`, then this file, then `docs/implementation-plan.md`, then `docs/finding-schema.md` and `common/record.py`.
