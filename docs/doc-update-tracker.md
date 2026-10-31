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
| 3 | Must / Should / Could, hour-2 gate, A/B split, fixtures | `docs/implementation-plan.md` | done |
| 4 | Agent rules | `AGENTS.md` | done |
| 5 | Consistency check, mermaid render, summary | all four | done |
| 6 | Addendum: Semgrep made optional (Stage 2 replaced) | all four | done |
| 7 | Addendum: back-guided static search for sweep hits | all four | done |

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

| # | Question | Where it shows |
|---|---|---|
| 1 | Who builds stage 3 (hypotheses)? The split names stages 0, 1, 2, 4, 5, 6, 7 only. Proposed: Person A. | plan |
| 2 | Who writes the seven fixtures? Proposed: Person A. | plan |
| 3 | Where does the probe engine live? `docs/repo-structure.md` puts HTTP code under `producers/dast/` (Person A) and says the engine never fires HTTP. The split gives the probe engine to Person B. | plan, `repo-structure.md` |
| 4 | The Must tier is planned for 4 to 5 hours and the gate is at hour 2. The own sink finder, secrets pass and catalogue are now Must scope. The user says time is not a concern. The numbers are unchanged. Raise the estimate and move the gate? | plan |
| 5 | JAX-RS adapter and B-5 scan comparison: not in the new tier lists. Placed in Could as proposed. | plan |
| 6 | Path traversal: the oracle list includes it, the Must item says four classes. Treated as stretch. | architecture, plan |
| 7 | If only the primary sink is exported, the other candidate sinks in an ambiguous group drop out of the SAST export. Code detection counts SAST findings by file and line. Do alternatives also stay as separate findings? | schema |
| 8 | Fallback dedupe key for findings with no `sink_id` (runtime-only, unlinked sweep hits, headers). | schema |
| 9 | Do `handler_file` and `handler_line_start` / `_end` stay? Tier A and Tier B are gone, so no consumer remains. | schema |
| 10 | Confidence scale after the A/B/C tiers are dropped. Also whether `confidence_reasons` is a field of its own. | schema |
| 11 | Source of the context path. Detection of the base URL at judging while staying localhost-only. | architecture |
| 12 | Defaults for `export.suppress_no_http_path` and for suppression overall. Needs a VulnerableApp run with and without suppression. | architecture |
| 13 | `blocked_by_validation` (probe note) maps to `status: blocked`. Confirm. | architecture |
| 14 | Tier of two AI tasks the brief does not rank: spec proposals for custom wrappers, and fix text. | architecture |
| 15 | The existing Semgrep runner guesses `param` and the existing ZAP runner owns verdicts. Both conflict with the new rules, and existing tests encode the old behaviour. Semgrep is also a regular dependency in `pyproject.toml`. | plan |
| 16 | The five existing fixtures use the tier-based shape. Rewrite or retire. | plan |
| 17 | The 35 of 45 figure came from an earlier run of the Semgrep rule set. Re-run it before using it as the promotion gate. | plan, architecture |
| 18 | Sink catalogue and secrets-rule YAML formats are undefined. Receiver-type matching needs resolved types. What matches when the receiver type is unresolved? | architecture |
| 19 | Field `corroborated` and flag `semgrep.enabled` are proposed names. | schema, architecture |
| 21 | Back-guided search: with the same catalogue and call graph it finds nothing stage 2 missed. What does it use that stage 2 does not? Proposed: relaxed matching and unresolved calls. | architecture |
| 22 | Tier and owner of the back-guided search. Proposed: Should, Person B. | plan |
| 23 | A sweep hit that links to a sink already marked `tested_negative`: which result wins? | architecture |
| 24 | `link_origin` is a proposed field. Should sweep-derived links get `link_status` at all, or only `link_origin`? | schema |
| 20 | Catalogue quality now drives recall. The tier of AI spec proposals (Should or Could) matters more than before. | architecture |

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
- Define the sink catalogue and secrets-rule YAML formats. Entropy thresholds.
- Make Semgrep an optional dependency and make its tests skip when it is absent.
