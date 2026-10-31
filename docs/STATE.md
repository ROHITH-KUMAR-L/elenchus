# STATE

Rules: one file, overwritten at each save, never a log. Maximum 150 lines. Nothing is marked passed unless it was run in this repo.

## 1. Last updated

2026-10-31. Trigger: the user answered the open questions. Decisions R1 to R8 were applied, and the tracker was folded into this file. Branch `docs/merged-architecture`. Local only. Not pushed.

## 2. Architecture

Static-guided dynamic testing. Static analysis makes hypotheses. The probe engine tests them. A directed hit is linked by `hypothesis_id` lineage.

- Stages: 0 preflight, 1 code index, 2 static, 3 hypotheses, 4 probe engine, 5 correlation, 6 verify, 7 output.
- Stage 2 is the own sink finder and secrets/crypto pass. Semgrep is an optional adapter, off by default.
- A firing probe proves route, param and CWE. It does not prove which sink on that route is the cause.
- Residual risk is same-route sink ambiguity, marked with `link_status: ambiguous`.
- Detail: `docs/architecture.md`. Contract: `docs/finding-schema.md`. Plan and split: `docs/implementation-plan.md`. Ownership map: `docs/repo-structure.md`.

## 3. Decisions locked

- D1: back-guided search is Should, Person A, relaxed mode only, off until measured.
- D2: a positive oracle versus `tested_negative` is replayed up to 3 times. 2 of 3 un-suppresses.
- D3: `link_status` and `link_origin` are both required and orthogonal.
- D4: milestones M1 to M3 replace hour gates. The own flow engine is Should, after M2.
- D5: contract fields `match_mode`, `unresolved_hops`, `candidate_sinks`, `conflict`, `oracle_flaky`.
- R1: the `tested_negative` adequacy logic and a suppressed file with real content are M2.
- R2: Person A owns stages 1, 2, 3, back-guided search, flow engine, fixtures. Person B owns stages 0, 4 to 7, `expected_pairs`, judging profile, fixture review.
- R2: stage 3 emits one Hypothesis record type for the directed and sweep sets.
- R3: the HTTP probe code is Person B's. Proposed directory `probe/`. Not created.
- R4: alternative sinks go in the SAST grader payload (`export.include_alternatives`, default true). They are attributes of the primary issue in the report.
- R5: the flow-engine gate is a new Semgrep count with unfitted rules. The old figure overstates.
- R6: N = 3 unresolved hops. `match_mode` defaults to `strict`.
- R6: a conflict case has `link_origin: sweep`, `link_status: ambiguous`, `conflict: true`, label Confirmed at low confidence, exported as Confirmed at or above `backguided.min_confidence_to_confirm`.
- R8: the M1 and M2 split of the Must items is accepted.
- No id: Semgrep is optional. No pipeline stage imports or requires it.
- No id: the own probe engine owns every runtime verdict. ZAP is optional and off in judging mode.
- No id: AI never creates or deletes a finding, sets a verdict, or decides a link.
- No id: header and cookie findings are never force-linked.

## 4. Milestone status

| Milestone | Status | Evidence |
|---|---|---|
| M1 spine | not started | None. No run of the new design on VulnerableApp. |
| M2 core | not started | None. |
| M3 extras | not started | None. |

## 5. Done

Docs on this branch: `AGENTS.md`, `CONTRIBUTING.md`, `docs/architecture.md`, `docs/finding-schema.md`, `docs/implementation-plan.md`, `docs/repo-structure.md`, `docs/STATE.md`. Banners on `README.md` and `docs/decisions.md`. `tests/README.md` deleted. The tracker is deleted in the last commit.

Code from earlier work, built for the older architecture:

- `producers/sast/spring_routes.py`: Spring route-map parser.
- `producers/sast/semgrep_runner.py`, `rules/`: Semgrep runner and rules.
- `producers/dast/zap_runner.py`: ZAP runner with oracle checks.
- `engine/`: tier-based correlation, Postgres store, text and SARIF reports.
- `cli/main.py`, `common/record.py`, `common/vocabulary.py`, `infra/compose.yaml`, `.github/workflows/ci.yml`, five fixtures.
- Authorship by commit count: the parser, Semgrep runner and `common/` are mostly the `rohithsp` identity. The engine, store, CLI, ZAP runner and CI are mostly `ROHITH-KUMAR-L`.

What ran: `uv run python -m pytest -q` at save time: 66 passed. These tests cover the older components. They say nothing about M1 to M3.

Measured: nothing is recorded. Semgrep yardstick: `[TODO: Semgrep count on VulnerableApp with unfitted rules; record count, date and rule version in STATE.md]`

Not run in this session: a VulnerableApp scan, ZAP, Docker.

## 6. Not done, in dependency order

1. Update `common/record.py`, the engine and the fixtures to the revised record (joint change with Person B).
2. Re-run Semgrep on VulnerableApp with unfitted rules. Record the count, date and rule version in section 5. Person A runs this.
3. Define the sink catalogue and secrets rule YAML formats.
4. Make Semgrep an optional dependency so tests pass without it.
5. Rewrite `README.md` before submission and before the demo run. It still carries pre-redesign content under its banner.
6. Move DAST directory ownership to B and create `probe/` when code starts.
7. Stage 1: extend the route-map parser to the code index (param types, call graph, sink inventory, unresolved-call flags).
8. Stage 2 and 3: own sink finder, secrets/crypto pass, hypotheses.
9. Stage 0 and 4: preflight, probe engine, baseline gate, differential oracles, canary, replay log.
10. Stage 5 to 7: correlation rework, `tested_negative` logic, suppressed file, scoring config, `expected_pairs`, benchmark adapter.
11. Judging-mode profile.
12. Should items: back-guided search, own flow engine, session manager, AI items.

Other TODO marks live in the docs. List them with `grep -rn "TODO" docs AGENTS.md`.

## 7. Known failures and residual flaws

- The existing Semgrep runner guesses `param`. The existing ZAP runner owns verdicts. Both conflict with the new rules.
- Semgrep is a regular dependency in `pyproject.toml`. The new rule is that tests pass without it.
- The five fixtures use the old tier shape.
- Same-route sink ambiguity. `TRACE` is unavailable at judging.
- A third sink that was never found can give a misleading link.
- Second-order bugs need route pairs. IDOR and business logic have no oracle. Blind SSRF and XXE need callbacks.
- Recall depends on the sink catalogue. Custom wrappers are missed.
- Stale: `README.md` and `docs/decisions.md` carry a banner. The READMEs in `common/`, `producers/`, `engine/` and `cli/` still carry old ownership and tier wording.
- Superseded decisions in `docs/decisions.md`: D-04, D-05, D-06, D-07, D-08, D-14, D-16, D-17.

## 8. Open questions for the user

- JAX-RS adapter and scan comparison (B-5) sit in Could as proposed. Confirm.
- Path traversal: its oracle is listed, Must says four classes. Treated as stretch. Confirm.
- Fallback dedupe key for findings with no `sink_id`.
- Keep or drop `handler_file`, `handler_line_start`, `handler_line_end`.
- Confidence scale. Is `confidence_reasons` a field of its own?
- Source of the context path. Base URL detection at judging while staying localhost-only.
- Default for `export.suppress_no_http_path` and for suppression overall.
- Does `blocked_by_validation` map to `status: blocked`?
- Tier of two AI tasks: spec proposals for custom wrappers, and fix text.
- Stage 2 with an unresolved receiver: flag only, or fall back?
- Proposed names: `corroborated`, `semgrep.enabled`, `backguided.enabled`, `backguided.min_confidence_to_confirm`, `export.include_alternatives`.
- `oracle_flaky` sits inside the evidence entry. `conflict` is a boolean. Confirm.
- Label of a conflict case below the `backguided.min_confidence_to_confirm` threshold.
- Subdirectory for stage 3 under `producers/`.
- Update the four directory READMEs now, or with the code?

## 9. Next action

Open `docs/finding-schema.md`. Update `common/record.py` to the revised record. It is a joint change, so tell Person B first.

## 10. Resume instructions

Read `AGENTS.md`, then this file, then `docs/finding-schema.md` and `common/record.py`.
