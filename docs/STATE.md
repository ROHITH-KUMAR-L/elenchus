# STATE

Rules: one file, overwritten at each save, never a log. Maximum 150 lines. Nothing is marked passed unless it was run in this repo.

## 1. Last updated

2026-10-31. Trigger: the handoff rule was added to `AGENTS.md`, and decisions D1 to D5 were applied to the planning docs. Branch `docs/merged-architecture`. Local only. Not pushed.

## 2. Architecture

Static-guided dynamic testing. Static analysis makes hypotheses. The probe engine tests them. A directed hit is linked by `hypothesis_id` lineage.

- Stages: 0 preflight, 1 code index, 2 static, 3 hypotheses, 4 probe engine, 5 correlation, 6 verify, 7 output.
- Stage 2 is the own sink finder and secrets/crypto pass. Semgrep is an optional adapter, off by default.
- A firing probe proves route, param and CWE. It does not prove which sink on that route is the cause.
- Residual risk is same-route sink ambiguity, marked with `link_status: ambiguous`.
- Detail: `docs/architecture.md`. Contract: `docs/finding-schema.md`. Plan: `docs/implementation-plan.md`.

## 3. Decisions locked

- D1: back-guided search is Should, Person A, relaxed mode only, off until measured.
- D2: positive oracle versus `tested_negative` is replayed up to 3 times. 2 of 3 un-suppresses.
- D3: `link_status` and `link_origin` are both required and orthogonal.
- D4: milestones M1 to M3 replace hour gates. The own flow engine is Should, after M2.
- D5: contract fields added: `match_mode`, `unresolved_hops`, `candidate_sinks`, `conflict`, `oracle_flaky`.
- No id: Semgrep is optional. No pipeline stage imports or requires it.
- No id: the own probe engine owns every runtime verdict. ZAP is optional and off in judging mode.
- No id: AI never creates or deletes a finding, sets a verdict, or decides a link.
- No id: header and cookie findings are never force-linked.
- No id: `tested_negative` findings are suppressed from the primary report and graded export.

## 4. Milestone status

| Milestone | Status | Evidence |
|---|---|---|
| M1 spine | not started | None. No run of the new design on VulnerableApp. |
| M2 core | not started | None. |
| M3 extras | not started | None. |

## 5. Done

Docs, this branch: `AGENTS.md`, `docs/architecture.md`, `docs/finding-schema.md`, `docs/implementation-plan.md`, `docs/doc-update-tracker.md`, `docs/STATE.md`. Cleanup (banners, one deletion) is the third commit on this branch.

Code from earlier work, built for the older architecture:

- `producers/sast/spring_routes.py`: Spring route-map parser.
- `producers/sast/semgrep_runner.py`, `rules/`: Semgrep runner and rules.
- `producers/dast/zap_runner.py`: ZAP runner with oracle checks.
- `engine/`: tier-based correlation, Postgres store, text and SARIF reports.
- `cli/main.py`, `common/record.py`, `common/vocabulary.py`, `infra/compose.yaml`, five fixtures.

What ran: `uv run python -m pytest -q` at save time: 66 passed. These tests cover the older components. They say nothing about M1 to M3.

Not run in this session: a VulnerableApp scan, ZAP, Docker.

## 6. Not done, in dependency order

1. Update `common/record.py` to the revised record (joint change). Rewrite the fixtures.
2. Stage 1: extend the route-map parser to the code index (param types, call graph, sink inventory, unresolved-call flags).
3. Stage 2: own sink finder, sink catalogue YAML, secrets/crypto pass.
4. Stage 3: hypotheses. Owner not decided.
5. Stage 0 and stage 4: preflight, probe engine, baseline gate, differential oracles, canary, replay log.
6. Stage 5 and 6: correlation rework, `tested_negative` logic, conflict rule.
7. Stage 7: scoring config, suppressed file, benchmark adapter, `expected_pairs` file.
8. Judging-mode profile.
9. Should items: back-guided search, own flow engine, session manager, AI items.

## 7. Known failures and residual flaws

- The existing Semgrep runner guesses `param`. The existing ZAP runner owns verdicts. Both conflict with the new rules.
- Semgrep is a regular dependency in `pyproject.toml`. The new rule is that tests pass without it.
- The five fixtures use the old tier shape.
- The 35 of 45 flow-engine gate comes from an earlier run of the old Semgrep rules. It has not been re-run.
- Same-route sink ambiguity. `TRACE` is unavailable at judging.
- A third sink that was never found can give a misleading link.
- Second-order bugs need route pairs. IDOR and business logic have no oracle. Blind SSRF and XXE need callbacks.
- Recall depends on the sink catalogue. Custom wrappers are missed.
- `README.md`, `docs/decisions.md`, `docs/repo-structure.md` are stale. They carry a banner.

## 8. Open questions for the user

Full list: `docs/doc-update-tracker.md` (22 items). Main ones:

- Who builds stage 3? Who writes the fixtures?
- Where does the probe engine live? `docs/repo-structure.md` says HTTP code is Person A's and the engine never fires HTTP.
- The suppressed file is M2, but the `tested_negative` logic is Should.
- Do alternative sinks stay in the SAST export? Code detection counts them.
- Keep or delete `docs/doc-update-tracker.md`?

## 9. Next action

Open `docs/finding-schema.md`. Update `common/record.py` to the revised record. It is a joint change, so tell Person B first.

## 10. Resume instructions

Read `AGENTS.md`, then this file, then `docs/finding-schema.md` and `common/record.py`.
