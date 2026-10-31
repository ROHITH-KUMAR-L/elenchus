# Doc update tracker

Tracks the revision of four planning docs to the static-guided dynamic testing architecture. Delete this file once the stale docs below are updated.

Scope: docs only. Edited files: `AGENTS.md`, `docs/architecture.md`, `docs/finding-schema.md`, `docs/implementation-plan.md`. Not edited: `README.md`, `docs/decisions.md`, `docs/repo-structure.md`, `docs/prd.md`. Work is on `main`.

Nothing in the revised docs is built, tested or measured by this change. They describe a target state.

## Stages

| # | Stage | File | Status |
|---|---|---|---|
| 0 | Create tracker, read the four docs, check existing code | this file | done |
| 1 | Contract first: new fields, replaced fields, hypothesis shape, examples, SARIF note | `docs/finding-schema.md` | done |
| 2 | Pipeline 0 to 7, judging mode, ambiguity, graded vs suppressed export, residual flaws, topology | `docs/architecture.md` | done |
| 3 | Must / Should / Could, first gate, A/B split, fixtures | `docs/implementation-plan.md` | done |
| 4 | Agent rules | `AGENTS.md` | done |
| 5 | Consistency check, mermaid render, summary | all four | done |
| 6 | Addendum: Semgrep made optional (Stage 2 replaced) | all four | done |
| 7 | Addendum: back-guided static search for sweep hits | all four | done |
| 8 | Settled decisions D1 to D5 applied. Hour gates replaced by milestones M1 to M3. | architecture, schema, plan, AGENTS | done |

Stage 5 checks run: banned phrases (only the rule text in `AGENTS.md`), old terms (only in the change-mapping tables), relative links and anchors (no problems), three Mermaid diagrams rendered. The Mermaid render was a syntax check. No code was run.

## Superseded decisions

`docs/decisions.md` is not edited in this pass. These entries no longer match the revised docs.

| Entry | Change |
|---|---|
| D-04 | Semgrep is no longer in the pipeline. It is an optional adapter. The CodeQL comparison still holds. |
| D-05 | Semgrep taint mode is gone from the pipeline. The own sink finder and secrets pass (YAML catalogue, no dataflow) find sinks. The call graph gives route and call path. No stage supplies the param. |
| D-06 | ZAP is no longer the core DAST. The own probe engine owns every verdict. ZAP is an optional passive pass. |
| D-07 | Tiers A/B/C and `reached_via` are replaced by evidence types and `entry_paths`. |
| D-08 | Kept in spirit. The AI rules are now stated in full in `AGENTS.md`. |
| D-14 | Placement note changes: the probe engine is the own HTTP client. ZAP is optional and off in judging mode. |
| D-16 | The producer entries change. Static and probe stages are now separate, and probes consume hypotheses. |
| D-17 | Dedupe key becomes `(sink_id, cwe)`. `severity` stays the producer's claim. `risk_score` comes from config. |

## Stale files not touched

| File | Why it is stale |
|---|---|
| `README.md` | Tier A/B/C table, ZAP as DAST, `reached_via`, oracle table. |
| `docs/decisions.md` | See the table above. |
| `docs/repo-structure.md` | Ownership split, "engine never fires HTTP", `run_dast` entry, fixtures list, `dedupe_key` rule. |
| `CONTRIBUTING.md`, `common/README.md`, `producers/README.md`, `engine/README.md`, `cli/README.md` | Outside the four-file scope. Same ownership and entry-point wording. |

## Open questions

Resolved by D1 to D4: the back-guided tier, owner and relaxed mode; the conflict rule; `link_origin` with `link_status`; the time estimate.

| # | Question | Where it shows |
|---|---|---|
| 1 | Who builds stage 3 (hypotheses)? Proposed: Person A. | plan |
| 2 | Who writes the fixtures? Proposed: Person A. | plan |
| 3 | Where does the probe engine live? `docs/repo-structure.md` puts HTTP code under `producers/dast/` (Person A) and says the engine never fires HTTP. The split gives the probe engine to Person B. | plan, `repo-structure.md` |
| 4 | JAX-RS adapter and B-5 scan comparison: not in the tier lists. Placed in Could as proposed. | plan |
| 5 | Path traversal: the oracle list includes it, the Must item says four classes. Treated as stretch. | architecture, plan |
| 6 | If only the primary sink is exported, the other candidate sinks in an ambiguous group drop out of the SAST export. Code detection counts SAST findings by file and line. Do alternatives also stay as separate findings? | schema |
| 7 | Fallback dedupe key for findings with no `sink_id`. | schema |
| 8 | Do `handler_file` and `handler_line_start` / `_end` stay? No consumer remains. | schema |
| 9 | Confidence scale after the A/B/C tiers are dropped. Also whether `confidence_reasons` is a field of its own. | schema |
| 10 | Source of the context path. Detection of the base URL at judging while staying localhost-only. | architecture |
| 11 | Defaults for `export.suppress_no_http_path` and for suppression overall. | architecture |
| 12 | `blocked_by_validation` maps to `status: blocked`. Confirm. | architecture |
| 13 | Tier of two AI tasks: spec proposals for custom wrappers, and fix text. Catalogue quality drives recall, so this matters. | architecture |
| 14 | The existing Semgrep runner guesses `param` and the existing ZAP runner owns verdicts. Existing tests encode that. Semgrep is a regular dependency. | plan |
| 15 | The five existing fixtures use the tier-based shape. Rewrite or retire. | plan |
| 16 | The 35 of 45 figure came from an earlier run of the Semgrep rule set. Re-run it before using it as the flow-engine gate. | plan, architecture |
| 17 | Sink catalogue and secrets-rule YAML formats. What matches when a receiver type is unresolved in strict mode? | architecture |
| 18 | `corroborated`, `semgrep.enabled`, `backguided.enabled` and `backguided.min_confidence_to_confirm` are proposed names. | schema, architecture |
| 19 | Tier conflict: the suppressed file is M2, but the `tested_negative` logic that fills it is Should. Proposed: M2 writes an empty file until the logic exists. | plan |
| 20 | Proposed values: N = 3 unresolved hops, the meaning of `link_origin: sweep`, `link_origin: sweep` on the conflict case, label Confirmed with low confidence after a conflict, `match_mode: strict`, `oracle_flaky` inside the evidence entry. | schema, architecture |
| 21 | The split of Must items into M1 and M2 is proposed. | plan |
| 22 | `docs/doc-update-tracker.md` overlaps `docs/STATE.md` for open questions. Keep or delete? | repo |

## TODOs

- Update `common/record.py`, the engine and the fixtures to the revised record (joint change).
- Ratify stage signatures and the `CodeIndex` shape.
- Confidence scale and risk-score config (CWE severity table, exploit factor, link factor).
- Time budget per stage, judging profile.
- Flag name for counting one sink with several routes.
- Header counting: per URL or per app.
- SARIF: GitHub code-scanning tag format, `suppressions` support, Runtime-only export, `webRequest` / `webResponse`.
- CI severity threshold.
- Postgres credentials handling, exact start and run commands.
- Path of the `expected_pairs` file (proposed `common/fixtures/expected_pairs/vulnerableapp.yaml`).
- Measure ambiguity rate on VulnerableApp.
- Verify that `engine/store/` and `engine/report/` take the new fields.
- Run VulnerableApp with and without AI. Report the recall and link delta.
- Set `backguided.min_confidence_to_confirm`. Measure the back-guided search on and off against `expected_pairs`.
- Define the sink catalogue and secrets-rule YAML formats. Entropy thresholds.
- Make Semgrep an optional dependency and make its tests skip when it is absent.
