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
- Confidence is a float from 0 to 1, a deterministic function of the evidence present, `link_status` and `link_origin`. Bands and scoring weights live in config. Cut points are tuned on `expected_pairs` runs.
- `confidence_reasons` is a list of `{factor, delta}`. The engine (Person B) writes it. Producers never set it. It is a contract field added before the freeze.
- Back-guided confidence starts at `backguided.start_confidence` and loses `backguided.hop_penalty` per unresolved hop. Below `backguided.min_confidence_to_confirm` the finding stays Runtime-only. A conflict case usually falls below it and exports as Runtime-only with `conflict: true`.
- Header counting follows config `header.count_mode` `[TODO: confirm at kickoff against the answer key]`.
- Back-guided search (Should, owner Person A) is for runtime-only hits with no hypothesis. It runs in relaxed mode only: call name alone when the receiver type is unresolved, up to `backguided.max_unresolved_hops` unresolved hops, with `unresolved_hops` and `match_mode: relaxed` recorded. Strict mode is the default `match_mode`. It matches only when the receiver type resolves, and the stage 2 hypotheses already cover it.
- One candidate sink gives `link_origin: back_guided`, `link_status: unique`, low confidence. Label it Confirmed only at or above `backguided.min_confidence_to_confirm`. Several candidates stay Runtime-only, `ambiguous`, with `candidate_sinks` as hints. Export no Confirmed link for them.
- `backguided.enabled` stays off until measured. Measure with it on and off against `expected_pairs`. If it adds no correct links, or adds any wrong link, leave it off.
- Conflict rule: an `ORACLE` hit on a `(route, param, CWE)` that matches a `tested_negative` sink is replayed up to `replay.count` times. At least `replay.min_hits` firing: un-suppress, clear `tested_negative`, set `link_origin: sweep`, `link_status: ambiguous` and `conflict: true`, record the reason "directed probes negative, positive hit on replay", lower the confidence, move it to the primary report. At or above `backguided.min_confidence_to_confirm`: label Confirmed. Below it: label Runtime-only, keep `conflict: true` and `link_status: ambiguous`, list the sink in `candidate_sinks` as a hint, export no Confirmed link. Not reproduced: keep `tested_negative`, set `oracle_flaky: true` on the evidence entry, make no link, leave the hit Runtime-only.
- Never run back-guided search on, or force-link, header, cookie or info-leak findings.

## Static stage rules

- The own sink finder (tree-sitter plus a per-CWE YAML catalogue) finds sinks. The own secrets and crypto pass finds hard-coded secrets and weak crypto. Rules live in YAML. The call graph gives the route and the call path.
- No pipeline stage may import or require Semgrep. Semgrep is an optional adapter, off by default, enabled by `semgrep.enabled`. The pipeline and its tests must pass with Semgrep not installed.
- Semgrep is allowed as a fallback sink source for a non-Java target, as a cross-check that marks corroborated sinks, and as an offline benchmark yardstick.
- The static stage does not say which param reaches the sink. Never fill `param` from static output. Fill `candidate_params` with all params of the route. The oracle resolves `param`.
- The own flow engine is Should, built after M2. It never blocks M1 or M2. Gate for making it the default: it matches the measured Semgrep count on VulnerableApp, with Semgrep run offline. `[TODO: Semgrep count on VulnerableApp with unfitted rules; record count, date and rule version in STATE.md]` The earlier figure came from rules partly fitted to VulnerableApp and overstates generality.
- Unresolved calls are flagged. Never drop them. Call sites that match a catalogue name with an unresolved receiver stay in the index. Only the relaxed back-guided search uses them. Never add a fallback to strict mode.

## Deterministic core, AI advisory

- Oracles decide every runtime verdict. Never let an LLM decide that an exploit worked.
- Correlation is deterministic. Confidence is a function of the evidence present. Store the reasons. Weights live in config.
- The pipeline must pass its tests with AI off.

AI hard rules:

- All AI is off by default (`ai.enabled`) and off in judging mode.
- AI never creates or deletes a finding.
- AI never sets an oracle verdict.
- AI never decides a link.
- AI may demote confidence. Judging `tested_negative` findings is Could and demotes only, with a written reason.
- Every AI output is validated against a JSON schema, cached by content hash and call-budgeted (`ai.max_calls`).
- Use AI only where the task is fuzzy, the output is machine-checkable and a wrong answer is caught. Tiers: Should (M3): fix text and link explanations, seeds from DTOs with repair (only after non-AI typed seeds work), the with/without measurement harness (built before any AI task). Could: source, sink and sanitiser spec proposals (must name real symbols), payload variants when blocked (the oracle decides, strict budget), judging `tested_negative` findings.
- No AI task becomes default-on until a with/without run on VulnerableApp against `expected_pairs` shows no loss in correct links or false alarms.

AI measurement: run VulnerableApp with and without AI. Report the recall and link difference. Do not report AI as helping without that run.

## Suppressed export rule

- A finding with `status: tested_negative` is suppressed. Keep it in Postgres.
- Exclude suppressed findings from the primary report and the graded export. Write them to the separate suppressed file.
- Status is assigned in this order: oracle fired (linked); no route reaches the sink (`no_http_path`); any candidate param `blocked_by_validation` with no oracle fired (`blocked`); every param probed, baseline valid, all payload families tried within budget (`tested_negative`); otherwise `untested`.
- Config flags: `export.include_suppressed` and `export.suppress_no_http_path`. Values: [Config reference in docs/architecture.md](docs/architecture.md#config-reference).
- `no_http_path` has a reason code: `no_callers` or `walk_unresolved`. Only `no_callers` findings in injection CWEs are ever eligible for suppression. Never suppress `walk_unresolved` or secrets/crypto findings.
- The SAST grader payload includes primary and alternative sinks (`export.include_alternatives`). In the primary report, alternatives are attributes of the primary issue, not separate issues.
- Secrets and crypto findings (CWE-798 and similar) are Code-only by nature. Never label them `no_http_path`.

## Judging mode

The organisers run the target. In judging mode:

- No log tail. No target restarts.
- The target base URL is the only required input (`--target` or an environment variable). Detect the context path and routes. Assume nothing. Never guess the context path silently.
- One command to run.
- A time budget per stage. Total runtime stays under 5 minutes.
- AI off.
- ZAP off.
- Semgrep off.
- `judging.profile` forces `semgrep.enabled`, `zap.enabled`, `logtail.enabled` and `ai.enabled` to false.

## Schema first

- The internal finding record is the contract. Code in `common/` is canonical. [docs/finding-schema.md](docs/finding-schema.md) describes it. Read and write only that shape.
- Do not add, rename or drop fields without updating that doc first.
- Use `normalise_route()` and the dedupe key function from `common/`. Never write a second route normaliser or key function. The key is `(sink_id, cwe)`.
- Keep `type` and `cwe` aligned to the VulnerableApp grader vocabulary.
- SARIF is ingest and export only. Never collapse the internal record into SARIF. Never pass SARIF between internal components.
- The SARIF export is lossy. The internal record is the source of truth.
- The VulnerableApp grader takes its own JSON. Do not send it SARIF.
- The `expected_pairs` file is for measurement only. It never feeds scanner logic.
- Config names and default values live only in the [Config reference in docs/architecture.md](docs/architecture.md#config-reference). Do not repeat values elsewhere. Keys are dotted lower_snake.

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
- Four vulnerability classes first: SQL injection, XSS, command injection, open redirect. Path traversal is Should, M3, the first item after M2.

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
