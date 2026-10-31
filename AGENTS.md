# AGENTS.md

Rules for AI coding agents working in this repo.

- Ownership source of truth: [docs/repo-structure.md](docs/repo-structure.md). Respect directory ownership. Never edit the schema in `common/` without flagging it as a joint change.

## Languages

- The tool is Python.
- The target app is Java / Spring Boot (primary). This can switch at kickoff through the adapter layer.
- Do not mix the two up. Never write tool code in Java. Never assume the target is Python.

## Deterministic core, AI advisory

- Oracles decide every runtime verdict. Never let an LLM decide that an exploit worked.
- Correlation is deterministic. AI must not create links or move any scored metric.
- AI may write fix text and link explanations. It may demote confidence. It must never delete a finding.

## Schema first

- The internal finding record in [docs/finding-schema.md](docs/finding-schema.md) is the contract. Read and write only that shape.
- Do not add, rename or drop fields without updating that doc first.
- Keep `type` and `cwe` aligned to the VulnerableApp grader vocabulary.
- SARIF is ingest and export only. Never collapse the internal record into SARIF. Never pass SARIF between internal components.
- The SARIF export is lossy. The internal record is the source of truth.
- The VulnerableApp grader takes its own JSON. Do not send it SARIF.

## Adapter boundary

- Framework-specific logic lives only in the SAST adapter and the route-map adapter.
- No Spring or JAX-RS assumptions in the core: no annotation names, no class layering rules.
- Route maps read annotation shapes. Never hard-code route names from the test app.

## Safety

- DAST targets `localhost` only. Never point ZAP or any scanner at another host. That is disqualification.
- Scan only the organisers' app or VulnerableApp, run locally from their Docker Compose.

## Our infrastructure

- Our Postgres runs on our own network and volume (proposed: `sastdast-net`, `sastdast-pgdata`, `sastdast-postgres`).
- Never wire our DB or tool onto the target's Docker network.
- Never expose Postgres beyond our network.
- Reach the target only over HTTP to `localhost:<port>`. DAST stays on localhost.
- Never commit DB credentials.

## Scope

- CLI only. Do not build a UI, API, server, login or cloud deployment.
- No automatic code fixes.
- One target framework per run.
- Four vulnerability types first. Path traversal is stretch.

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
| [docs/architecture.md](docs/architecture.md) | Components, data flow, correlation tiers, our infrastructure |
| [docs/decisions.md](docs/decisions.md) | Decisions and rejected alternatives |
| [docs/finding-schema.md](docs/finding-schema.md) | Internal finding record contract and SARIF mapping |
| [docs/implementation-plan.md](docs/implementation-plan.md) | Build order, tracks, cut list |
