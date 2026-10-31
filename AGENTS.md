# AGENTS.md

Rules for AI coding agents working in this repo.

- Ownership: the split in [docs/implementation-plan.md](docs/implementation-plan.md). Person A owns stages 1 and 2. Person B owns stages 0, 4, 5, 6 and 7. `common/` and `infra/` are joint. [docs/repo-structure.md](docs/repo-structure.md) is stale on this point until it is updated. Respect directory ownership.
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
- A sweep hit with no directed hypothesis may be linked by the back-guided static search. Mark it `link_origin: sweep_derived` and lower the confidence. If no sink is found, it stays Runtime-only.
- Never force-link header and cookie findings.

## Static stage rules

- The own sink finder (tree-sitter plus a per-CWE YAML catalogue) finds sinks. The own secrets and crypto pass finds hard-coded secrets and weak crypto. Rules live in YAML. The call graph gives the route and the call path.
- No pipeline stage may import or require Semgrep. Semgrep is an optional adapter, off by default, enabled by `semgrep.enabled`. The pipeline and its tests must pass with Semgrep not installed.
- Semgrep is allowed as a fallback sink source for a non-Java target, as a cross-check that marks corroborated sinks, and as an offline benchmark yardstick.
- The static stage does not say which param reaches the sink. Never fill `param` from static output. Fill `candidate_params` with all params of the route. The oracle resolves `param`.
- The own flow engine is Could. Do not build it before the hour-2 gate passes. Promotion gate: it matches Semgrep's 35 of 45 on VulnerableApp, with Semgrep run offline.
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

## Docs

| Doc | Content |
|---|---|
| [docs/prd.md](docs/prd.md) | Organisers' spec. Do not edit. |
| [docs/architecture.md](docs/architecture.md) | Pipeline, judging mode, ambiguity, export, residual flaws, topology |
| [docs/finding-schema.md](docs/finding-schema.md) | Internal finding record, hypothesis shape, SARIF mapping |
| [docs/implementation-plan.md](docs/implementation-plan.md) | Must, Should, Could, gate, split, fixtures |
| [docs/doc-update-tracker.md](docs/doc-update-tracker.md) | Stale docs and open questions from this revision |
| [docs/decisions.md](docs/decisions.md) | Decisions. Stale until the code runs. |

Only `AGENTS.md`, `architecture.md`, `finding-schema.md` and `implementation-plan.md` are kept current while coding.
