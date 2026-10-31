# STATE

Rules: one file, overwritten at each save, never a log. Maximum 150 lines. Nothing is marked passed unless it was run in this repo.

## 1. Last updated

2026-10-31. Trigger: user approved the architecture-limitation fixes and asked for build stages in place of the two-person split. Documentation only, plus one docstring line each in `cli/main.py` and `common/record.py`. No ZAP or VulnerableApp run.

## 2. Architecture

Static-guided dynamic testing. Static analysis makes hypotheses. OWASP ZAP performs active probes; project orchestration keeps hypothesis context and deterministic oracles own verdicts.

- Pipeline stages: 0 preflight, 1 code index, 2 static, 3 hypotheses, 4 ZAP-backed probe orchestration, 5 correlation, 6 verify, 7 output.
- Build stages: `BS0` onward. The order we build it in. Milestones are gates over them.
- Stage 2 is the own sink finder and secrets/crypto pass. Semgrep is an optional adapter, off by default.
- One ZAP job per `(route, method)`, one at a time. Param from a request diff, CWE from the rule ID, verdict from a coordinator replay. All unverified until `BS0`.
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
| M1 spine | `BS0` to `BS5` | not started | None |
| M2 core | `BS6` to `BS9` | not started | None |
| M3 extras | `BS10` | not started | None |

Current build stage: `BS0`. Not started.

## 5. Done

This update changed documentation and the two docstrings above: `AGENTS.md`, `CONTRIBUTING.md`, root `README.md`, `docs/README.md`, `docs/architecture.md`, `docs/finding-schema.md`, `docs/implementation-plan.md`, `docs/repo-structure.md`, `docs/STATE.md`, and the `README.md` in `producers/`, `engine/`, `cli/`, `common/` and `infra/`. Not committed. `docs/prd.md` and `docs/decisions.md` were not touched.

ZAP API names in the docs were checked against zaproxy.org docs, only partly word for word. They were not run.

Code from earlier work, built for the older architecture:

- `producers/sast/spring_routes.py`: Spring route-map parser.
- `producers/sast/semgrep_runner.py`, `rules/`: Semgrep runner and rules.
- `producers/dast/zap_runner.py`: ZAP runner with oracle checks.
- `engine/`: tier-based correlation, Postgres store, text and SARIF reports.
- `cli/main.py`, `common/record.py`, `common/vocabulary.py`, `infra/compose.yaml`, `.github/workflows/ci.yml`, five fixtures.

What ran: `uv run python -m pytest -q` in this update: 66 passed. Those tests cover the older components and say nothing about M1 to M3.

Measured: nothing. Semgrep yardstick: `[TODO: Semgrep count on VulnerableApp with unfitted rules; record count, date and rule version in STATE.md]`

## 6. Not done, in dependency order

The build stages in `docs/implementation-plan.md` are the list. None has started.

1. `BS0`: ZAP acceptance check
2. `BS1`: contract, config, fixtures
3. `BS2`: code index
4. `BS3`: SQL sinks and hypotheses
5. `BS4`: preflight and probe spine
6. `BS5`: end-to-end spine (M1 gate)
7. `BS6`: all classes and the scheduler
8. `BS7`: negative evidence, ambiguity, coverage
9. `BS8`: secrets, exports, measurement
10. `BS9`: judging mode and generality (M2 gate)
11. `BS10`: Should list (M3)
12. `BS11`: Could list

Other TODO marks live in the docs. List them with `grep -rn "TODO" docs AGENTS.md`.

## 7. Known failures and residual flaws

- The existing Semgrep runner guesses `param`. The existing ZAP runner reads alerts for the whole base URL and has no per-hypothesis workflow.
- Semgrep is a regular dependency in `pyproject.toml`. The new rule is that tests pass without it.
- The five fixtures use the old tier shape. `common/record.py` does not yet have the new fields, including `arg_shape`, `safe_pattern` and `ProbeJob`.
- The attribution design is unverified until `BS0`.
- About 30 routes leaves about 6 seconds per job. This is arithmetic. It may not fit.
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
- Config values still TODO: `probe.timing_repeats`, `probe.max_job_seconds`, `zap.thread_per_host`, `zap.version`. Budget, back-guided and band values are proposed, to be tuned on runs.
- Does the organisers' app need a login? Decides whether the session manager moves to `BS6`.
- Does VulnerableApp's source have safe variants usable as live decoys? Confirm when the source is available.
- From the README: the organisers' app framework (kickoff) and Semgrep rule-set version for the offline yardstick.
- From the stale `docs/decisions.md` (D-12): which VulnerableApp module stands in for the code-only path, crypto or JWT.
- Entry signatures to ratify in `BS1`.

## 9. Next action

Start `BS0`: pin a ZAP image, start VulnerableApp from its own Compose, and run the eight checks in `docs/architecture.md#zap-acceptance-check`. Known blocker: an earlier ZAP image pull failed with a connection reset.

## 10. Resume instructions

Read `AGENTS.md`, then this file, then `docs/implementation-plan.md`, then `docs/finding-schema.md` and `common/record.py`.
