# AGENTS.md

Rules for AI coding agents working in this repo.

- Ownership: the split in [docs/implementation-plan.md](docs/implementation-plan.md). Person A owns stages 1, 2 and 3, the back-guided search, the flow engine and the fixtures. Person B owns stages 0, 4, 5, 6 and 7, the `expected_pairs` file, the judging profile and fixture review. `common/` and `infra/` are joint. Directory ownership map: [docs/repo-structure.md](docs/repo-structure.md). Respect directory ownership.
- Never edit the schema in `common/` without flagging it as a joint change.

## Languages

- The tool is Python.
- The target app is Java / Spring Boot (primary). This can switch at kickoff through the adapter layer.
- Do not mix the two up. Never write tool code in Java. Never assume the target is Python.

## Architecture in one paragraph

Static-guided dynamic testing. Static analysis produces hypotheses. The probe engine tests them. Read [docs/architecture.md](docs/architecture.md) before changing any stage.

## Linking rules

- A directed hit is linked by hypothesis lineage. The `hypothesis_id` travels through the probe into the evidence. Do not link by matching afterwards.
- Never write "true by construction" or "toward zero" about wrong links.
- A firing probe proves that route, param and CWE are exploitable. It does not prove which sink on that route is the cause.
- Several hypotheses in one `(route, param, CWE)` group means `link_status: ambiguous`. Lower the confidence. Attach every candidate sink as an alternative. Pick one primary by the stated rule.
- Wrong links come from same-route sink ambiguity. Report how often it happens. Do not hide it.
- `TRACE` evidence needs the optional log tail. It is not available in judging mode. Do not rely on it.
- A third sink that was never found can still produce a misleading link. Say so where it matters.
- `link_status` (`unique` or `ambiguous`) and `link_origin` (`directed`, `sweep` or `back_guided`) are both required once a link exists. They are orthogonal. `link_origin` alone would hide ambiguity on sweep links.
- Confidence is a float from 0 to 1, a deterministic function of the evidence present, `link_status` and `link_origin`. Three named bands and the scoring weights live in config.
- Back-guided search (Should, owner Person A) is for runtime-only hits with no hypothesis. It runs in relaxed mode only: call name alone when the receiver type is unresolved, up to N = 3 unresolved hops, with `unresolved_hops` and `match_mode: relaxed` recorded. Strict mode is the default `match_mode` and is already covered by the stage 2 hypotheses.
- One candidate sink gives `link_origin: back_guided`, `link_status: unique`, low confidence. Label it Confirmed only at or above `backguided.min_confidence_to_confirm`. Several candidates stay Runtime-only, `ambiguous`, with `candidate_sinks` as hints. Export no Confirmed link for them.
- `backguided.enabled` is false until measured. Measure with it on and off against `expected_pairs`. If it adds no correct links, or adds any wrong link, leave it off.
- Conflict rule: an `ORACLE` hit on a `(route, param, CWE)` that matches a `tested_negative` sink is replayed up to 3 times. At least 2 of 3 firing: un-suppress, clear `tested_negative`, set `link_origin: sweep`, `link_status: ambiguous` and `conflict: true`, record the reason "directed probes negative, positive hit on replay", lower the confidence, move it to the primary report. At or above `backguided.min_confidence_to_confirm`: label Confirmed. Below it: label Runtime-only, keep `conflict: true` and `link_status: ambiguous`, list the sink in `candidate_sinks` as a hint, export no Confirmed link. Not reproduced: keep `tested_negative`, set `oracle_flaky: true` on the evidence entry, make no link, leave the hit Runtime-only.
- Never run back-guided search on, or force-link, header, cookie or info-leak findings.

## Static stage rules

- The own sink finder (tree-sitter plus a per-CWE YAML catalogue) finds sinks. The own secrets and crypto pass finds hard-coded secrets and weak crypto. Rules live in YAML. The call graph gives the route and the call path.
- No pipeline stage may import or require Semgrep. Semgrep is an optional adapter, off by default, enabled by `semgrep.enabled`. The pipeline and its tests must pass with Semgrep not installed.
- Semgrep is allowed as a fallback sink source for a non-Java target, as a cross-check that marks corroborated sinks, and as an offline benchmark yardstick.
- The static stage does not say which param reaches the sink. Never fill `param` from static output. Fill `candidate_params` with all params of the route. The oracle resolves `param`.
- The own flow engine is Should, built after M2. It never blocks M1 or M2. Gate for making it the default: it matches the measured Semgrep count on VulnerableApp, with Semgrep run offline. `[TODO: Semgrep count on VulnerableApp with unfitted rules; record count, date and rule version in STATE.md]` The earlier figure came from rules partly fitted to VulnerableApp and overstates generality.
- Unresolved calls are flagged. Never drop them.

## Deterministic core, AI advisory

- Oracles decide every runtime verdict. Never let an LLM decide that an exploit worked.
- Correlation is deterministic. Confidence is a function of the evidence present. Store the reasons. Weights live in config.
- The pipeline must pass its tests with AI off.

AI hard rules:

- AI never creates or deletes a finding.
- AI never sets an oracle verdict.
- AI never decides a link.
- AI may demote confidence, and may judge `tested_negative` findings. It demotes only, with a written reason.
- Every AI output is validated against a JSON schema, cached by content hash and call-budgeted.
- Use AI only where the task is fuzzy, the output is machine-checkable and a wrong answer is caught. Allowed tasks: propose source, sink and sanitiser specs for custom wrappers (must name real symbols); generate seeds from DTOs (the baseline must pass, at most 3 repairs); propose payload variants when blocked (the oracle decides, strict budget); judge `tested_negative` findings; write fix text.

AI measurement: run VulnerableApp with and without AI. Report the recall and link difference. Do not report AI as helping without that run.

## Suppressed export rule

- A finding with `status: tested_negative` is suppressed. Keep it in Postgres.
- Exclude suppressed findings from the primary report and the graded export. Write them to the separate suppressed file.
- `tested_negative` needs all three: baseline valid for every candidate param, every candidate param probed, all payload families for the CWE tried within budget. If any is missing, the status is `blocked` or `untested`.
- Config flags: `export.include_suppressed` (default false) and `export.suppress_no_http_path` (default false).
- The SAST grader payload includes primary and alternative sinks (`export.include_alternatives`, default true). In the primary report, alternatives are attributes of the primary issue, not separate issues.
- Secrets and crypto findings (CWE-798 and similar) are Code-only by nature. Never label them `no_http_path`.

## Judging mode

The organisers run the target. In judging mode:

- No log tail. No target restarts.
- Zero config. Detect the base URL, context path and routes. Assume nothing.
- One command to run.
- A time budget per stage. Total runtime stays under 5 minutes.
- AI off, or call-capped with a deterministic fallback.
- ZAP off.
- Semgrep off.

## Schema first

- The internal finding record is the contract. Code in `common/` is canonical. [docs/finding-schema.md](docs/finding-schema.md) describes it. Read and write only that shape.
- Do not add, rename or drop fields without updating that doc first.
- Use `normalise_route()` and the dedupe key function from `common/`. Never write a second route normaliser or key function. The key is `(sink_id, cwe)`.
- Keep `type` and `cwe` aligned to the VulnerableApp grader vocabulary.
- SARIF is ingest and export only. Never collapse the internal record into SARIF. Never pass SARIF between internal components.
- The SARIF export is lossy. The internal record is the source of truth.
- The VulnerableApp grader takes its own JSON. Do not send it SARIF.
- The `expected_pairs` file is for measurement only. It never feeds scanner logic.

## Adapter boundary

- Only stages 1 and 2 are framework-specific. They live behind the adapter.
- No Spring or JAX-RS assumptions in the probe engine, correlation or output: no annotation names, no class layering rules.
- The route table reads annotation shapes. Never hard-code route names from the test app.

## Safety

- DAST targets `localhost` only. Never point the probe engine, ZAP or any scanner at another host. That is disqualification.
- Scan only the organisers' app or VulnerableApp, run locally from their Docker Compose.
- Probe only routes in the route table. Send `X-Elenchus-Probe` and a canary id on every probe. Keep a replay log.
- Probes are safe test requests, as the PRD says for B-1.

## Our infrastructure

- Our Postgres runs on our own network and volume (proposed: `sastdast-net`, `sastdast-pgdata`, `sastdast-postgres`).
- Never wire our DB or tool onto the target's Docker network.
- Never expose Postgres beyond our network.
- Reach the target only over HTTP to `localhost:<port>`.
- Never commit DB credentials.

## Scope

- Time is not a constraint. Order work by dependency, not by clock. Milestones M1 to M3 replace hour gates.
- CLI only. Do not build a UI, API, server, login or cloud deployment.
- No automatic code fixes.
- One target framework per run.
- Four vulnerability classes first: SQL injection, XSS, command injection, open redirect. Path traversal is stretch.

## Honesty

- Nothing is tested or working until it has run. Say so.
- Never invent metrics, results, versions, endpoints or team details. Mark unknowns `[TODO: confirm at kickoff]`.

## Writing style

- Plain and direct. Short sentences. Tables over prose.
- No inflated significance, no "not just X but Y", no vague attributions, no filler, no emoji.

## Context handoff

Context handoff. Before the context window runs out, write the current system state to docs/STATE.md. Do it when any of these happens: you get a context or token warning; auto-compaction is announced; you are about to start a large multi-file task; a milestone completes; the user says 'save state'. Also read docs/STATE.md at the start of every session, after AGENTS.md. Do not wait for the last moment. If unsure whether you are close to the limit, save.

`docs/STATE.md` rules:

- One file. Overwrite it each time. Never append a log.
- Maximum 150 lines. Plain style.
- Keep the ten sections in the order the file already uses.
- Never mark anything passed or working unless it was run in this repo. State what was run.

## Docs

| Doc | Content |
|---|---|
| [docs/prd.md](docs/prd.md) | Organisers' spec. Do not edit. |
| [docs/architecture.md](docs/architecture.md) | Pipeline, judging mode, ambiguity, export, residual flaws, topology |
| [docs/finding-schema.md](docs/finding-schema.md) | Internal finding record, hypothesis shape, SARIF mapping |
| [docs/implementation-plan.md](docs/implementation-plan.md) | Milestones M1 to M3, tiers, split, fixtures |
| [docs/STATE.md](docs/STATE.md) | Current system state. Read at session start. Overwritten at each save. |
| [docs/decisions.md](docs/decisions.md) | Decisions. Stale until the code runs. |

Only `AGENTS.md`, `architecture.md`, `finding-schema.md` and `implementation-plan.md` are kept current while coding.
