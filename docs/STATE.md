# STATE

Rules: one file, overwritten at each save, never a log. Maximum 150 lines. Nothing is marked passed unless it was run in this repo.

## 1. Last updated

2026-10-31. Trigger: user selected ZAP as the active probe engine, including judging mode. Architecture, ownership, schema guidance, implementation plan, agent rules and README now reflect that target. Documentation only; no code change or ZAP run in this update.

## 2. Architecture

Static-guided dynamic testing. Static analysis makes hypotheses. OWASP ZAP performs active probes; project orchestration preserves hypothesis context and deterministic oracles own verdicts.

- Stages: 0 preflight, 1 code index, 2 static, 3 hypotheses, 4 ZAP-backed probe orchestration, 5 correlation, 6 verify, 7 output.
- Stage 2 is the own sink finder and secrets/crypto pass. Semgrep is an optional adapter, off by default.
- A firing probe proves route, param and CWE. It does not prove which sink on that route is the cause.
- Residual risk is same-route sink ambiguity, marked with `link_status: ambiguous`.
- ZAP active scanning is required, including judging mode. Per-hypothesis scan attribution, baseline gating, canary/header propagation, replay capture, and deterministic response verification still need implementation and measurement.
- Detail: `docs/architecture.md`. Contract: `docs/finding-schema.md`. Plan and split: `docs/implementation-plan.md`. Ownership map: `docs/repo-structure.md`.

## 3. Decisions locked

Config names and default values live in the Config reference in `docs/architecture.md`. This list does not repeat values.

- D1: back-guided search is Should, Person A, relaxed mode only, off until measured. Entry `run_back_guided`.
- D2: a positive oracle versus a `tested_negative` sink is replayed (`replay.count`, `replay.min_hits`). Enough hits un-suppress it.
- D3: `link_status` and `link_origin` are both required and orthogonal.
- D4: milestones M1 to M3 replace hour gates. The own flow engine is Should, after M2.
- D5: contract fields `match_mode`, `unresolved_hops`, `candidate_sinks`, `conflict`, `oracle_flaky`.
- R1: the `tested_negative` adequacy logic and a suppressed file with real content are M2.
- R2, R3: Person A owns stages 1 to 3, back-guided search, flow engine, fixtures. Person B owns stages 0 and 4 to 7, ZAP scan coordination and response-oracle validation, `expected_pairs`, the judging profile, fixture review. Proposed directories `probe/` and `producers/hypotheses/`. Neither exists.
- R2: stage 3 emits one Hypothesis record type for the directed and sweep sets.
- R4: alternative sinks go in the SAST grader payload. In the report they are attributes of the primary issue.
- R5: the flow-engine gate is a new Semgrep count with unfitted rules. The old figure overstates.
- R6: `match_mode` defaults to `strict`. A conflict case is Confirmed at or above the confirm threshold. Below it, it is Runtime-only with the sink in `candidate_sinks`, and it is not suppressed.
- F4: fallback dedupe keys. Secrets `(cwe, file, line)`. Runtime-only injection `(cwe, normalised_route, method, param)`. Headers `(cwe, header_name)`, per `header.count_mode`.
- G1 to G4: confidence is a float from 0 to 1 with three bands in config. `confidence_reasons` is a list of `{factor, delta}`, written by the engine only. Back-guided confidence comes from config.
- Q1: JAX-RS stays Could. It moves to Should only if the graded app is not Spring, and would earn B-7. B-5 is Should, M3.
- Q2: path traversal is Should, M3, the first item after M2. Oracle: a file-content marker `[proposed: passwd line pattern]`.
- Q3: `handler_*` leave the record. The route table keeps handler spans. `call_chain` items are `{method, file, line}`.
- Q4: the base URL is a required input (`--target`). The context path is detected in a fixed order and never guessed silently. The route table is built before preflight.
- Q5: `no_http_path` has reason codes `no_callers` and `walk_unresolved`. Only `no_callers` in injection CWEs can be suppressed. The flag is off until measured.
- Q6: `blocked_by_validation` is a per-param probe outcome with sub-codes. Status is assigned in a fixed order.
- Q7: all AI is off by default and in judging mode. No AI task is default-on without a with/without run.
- Q8: strict mode has no fallback for an unresolved receiver. The coverage report counts those call sites.
- Q9: config names are locked and live in one place.
- R7: ZAP is the active probe engine and is enabled in judging mode. Project code still owns orchestration, hypothesis provenance, response-oracle validation, and findings. AI never creates or deletes a finding, sets a verdict or decides a link. Header and cookie findings are never force-linked.

## 4. Milestone status

| Milestone | Status | Evidence |
|---|---|---|
| M1 spine | not started | None. No run of the new design on VulnerableApp. |
| M2 core | not started | None. |
| M3 extras | not started | None. |

## 5. Done

This update changed documentation only: `AGENTS.md`, root `README.md`, `docs/architecture.md`, `docs/finding-schema.md`, `docs/implementation-plan.md`, `docs/repo-structure.md` and `docs/STATE.md`. README now reflects the planned ZAP-backed architecture; revisit its usage section when the redesigned CLI is implemented. `docs/decisions.md` and `infra/README.md` remain stale or unchanged.

Code from earlier work, built for the older architecture:

- `producers/sast/spring_routes.py`: Spring route-map parser.
- `producers/sast/semgrep_runner.py`, `rules/`: Semgrep runner and rules.
- `producers/dast/zap_runner.py`: ZAP runner with oracle checks.
- `engine/`: tier-based correlation, Postgres store, text and SARIF reports.
- `cli/main.py`, `common/record.py`, `common/vocabulary.py`, `infra/compose.yaml`, `.github/workflows/ci.yml`, five fixtures.
- Authorship by commit count: the parser, Semgrep runner and `common/` are mostly the `rohithsp` identity. The engine, store, CLI, ZAP runner and CI are mostly `ROHITH-KUMAR-L`.

What ran: `uv run python -m pytest -q` at save time: 66 passed. These tests cover the older components. They say nothing about M1 to M3.

Measured: nothing is recorded. Semgrep yardstick (protocol in section 6, item 2): `[TODO: Semgrep count on VulnerableApp with unfitted rules; record count, date and rule version in STATE.md]`

Not run in this session: a VulnerableApp scan or ZAP scan. Docker image pull for ZAP failed due a connection reset.

## 6. Not done, in dependency order

1. Update `common/record.py`, the engine and the fixtures to the revised record (joint change with Person B). Drop `handler_*` from `record.py` and the fixtures. Use the new `call_chain` item shape `{method, file, line}`.
2. Semgrep yardstick. Use the public OWASP rule pack as shipped. Make no edits after seeing results. Run it once on VulnerableApp. Record the count, date and rule pack version in section 5. Person A runs this.
3. Define the sink catalogue and secrets rule YAML formats.
4. Make Semgrep an optional dependency so tests pass without it.
5. Reconcile stale `docs/decisions.md` after the new code is exercised; refresh README commands after the redesigned CLI exists.
6. Implement the documented Person B ZAP coordinator in `probe/` and integrate the ZAP API client in `producers/dast/`.
7. Stage 1: extend the route-map parser to the code index (param types, call graph, sink inventory, unresolved-call flags).
8. Stage 2 and 3: own sink finder, secrets/crypto pass, hypotheses (`producers/hypotheses/`).
9. Stage 0 and 4: preflight plus ZAP active-scan integration. Preserve baseline gates, per-hypothesis provenance, differential response oracles, canary/header propagation, and replay logs around ZAP requests.
10. Stage 5 to 7: correlation rework, `tested_negative` logic, suppressed file, scoring config, `expected_pairs`, benchmark adapter.
11. Measure `export.include_alternatives`. Run it on and off against `expected_pairs`. Record code detection and false-alarm rate for each. Keep the setting that meets the Great targets on both (code detection over 85%, false alarms under 10%). If both settings do, keep the one with the lower false-alarm rate. If neither does, keep the one with code detection above 60% and the lower false-alarm rate. Use the same protocol for `export.suppress_no_http_path`.
12. Judging-mode profile.
13. Should items, in this order: path traversal (first, after M2), back-guided search, own flow engine, scan comparison (B-5), session manager, AI items.

Other TODO marks live in the docs. List them with `grep -rn "TODO" docs AGENTS.md`.

## 7. Known failures and residual flaws

- The existing Semgrep runner guesses `param`. The existing ZAP runner accepts scanner alerts only after its current response checks; it does not yet support the redesigned per-hypothesis scan workflow.
- Semgrep is a regular dependency in `pyproject.toml`. The new rule is that tests pass without it.
- The five fixtures use the old tier shape.
- Same-route sink ambiguity. `TRACE` is unavailable at judging.
- A third sink that was never found can give a misleading link.
- Second-order bugs need route pairs. IDOR and business logic have no oracle. Blind SSRF and XXE need callbacks.
- Recall depends on the sink catalogue. Custom wrappers are missed.
- `docs/decisions.md` remains stale. Root README describes the target architecture and separately marks current commands as the older implementation.
- Superseded decisions in `docs/decisions.md`: D-04, D-05, D-06, D-07, D-08, D-14, D-16, D-17.

## 8. Open questions for the user

- Name of the environment variable for the base URL, the alternative to `--target`.
- Where the context path found by preflight is stored: `ScanTarget` or the preflight output.
- Path traversal: confirm the passwd line pattern. The split is Person A for the catalogue and hypotheses, Person B for the oracle.
- `oracle_flaky` sits inside the evidence entry. `conflict` is a boolean. Confirm.
- Header counting and multi-route export counting: confirm `header.count_mode` and `export.count_multi_entry` at kickoff against the answer key.
- Config values still TODO: `probe.max_attempts_per_hypothesis`, `probe.timing_repeats`, `probe.stage_budget_seconds.<stage>`. The back-guided and band values are proposed, to be tuned on `expected_pairs` runs.
- ZAP integration acceptance: verify hypothesis/job attribution, CWE/parameter-scoped coverage, canary/header propagation, request/response replay capture, and active-scan time limits against the pinned ZAP version.
- From the README rewrite: the organisers' app framework (kickoff), Semgrep rule-set version for the offline yardstick, and ZAP image/version.
- From the stale `docs/decisions.md` (D-12): which VulnerableApp module stands in for the code-only path, crypto or JWT. The other open items there are resolved or superseded.
- From `docs/repo-structure.md`: who is Person A and Person B (kickoff), the owners of `CONTRIBUTING.md`, `.gitignore` and `repo-structure.md`, and the entry signatures to ratify.

## 9. Next action

Begin the joint `common/record.py` contract update from `docs/finding-schema.md`; then implement the staged pipeline, including hypothesis-scoped ZAP active scans and response-oracle validation. Validate ZAP scan-job attribution and request metadata against a pinned ZAP image before claiming the integration works.

## 10. Resume instructions

Read `AGENTS.md`, then this file, then `docs/finding-schema.md` and `common/record.py`.
