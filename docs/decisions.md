# Decisions

ADR-style. Status: proposed unless marked otherwise. Nothing here is validated by a run.

## D-01 Tool in Python, target in Java / Spring Boot

- **Decision:** We write the tool in Python. The primary target is Java / Spring Boot.
- **Why:** Python has the ZAP client and fast scripting. VulnerableApp, our practice target, is Spring Boot on Java 17.
- **Rejected:** Writing the tool in Java to match the target. It adds build overhead and gives no correlation benefit.
- **Note:** Do not conflate the two. The target language can change at kickoff. The tool language does not.

## D-02 Framework-adapter architecture

- **Decision:** The core (ZAP, internal finding record, correlation, oracles) is framework-agnostic. Only the SAST rules and the route-map parser sit behind a per-framework adapter.
- **Why:** The organisers' app and the unseen app may differ. A swap then touches two components, not the whole tool.
- **Rejected:** One Spring-specific pipeline. It fails if kickoff reveals another framework.

## D-03 Spring MVC primary, JAX-RS secondary

- **Decision:** Build and harden the Spring MVC adapter first. Add JAX-RS behind the same interface.
- **Why:** Spring dominates enterprise Java. JAX-RS is the established second option. A second adapter shows the core is not Spring-only (B-7).
- **Rejected:** Building both at equal depth. That splits effort before the primary path works.
- **Note:** If kickoff shows a different target framework, harden that adapter first instead.

## D-04 Semgrep over CodeQL

- **Decision:** Use Semgrep for SAST in both adapters.
- **Why:** No build step. CodeQL needs a compile step for Java, which conflicts with the <5-minute run target.
- **Rejected:** CodeQL.

## D-05 Semgrep taint mode over pattern rules

- **Decision:** Use taint mode for the four injection classes. Use pattern or secret rules only for the secrets/crypto pass.
- **Why:** Taint mode tracks source-to-sink flow and respects sanitisers. Parameterised-query decoys do not fire. The trace is kept as evidence. Tier B uses call edges instead (D-07).
- **Rejected:** Pattern-only rules. They flag decoys and give no trace.

## D-06 ZAP over Nuclei for core DAST

- **Decision:** OWASP ZAP is core DAST. Nuclei is optional, bonus-only (known CVEs, misconfig).
- **Why:** The planted bugs are custom app flaws, not catalogued CVEs. ZAP's active scan finds injection. Its passive scan flags missing headers.
- **Rejected:** Nuclei as the core scanner.

## D-07 Confidence-tiered correlation, Tier B main path

- **Decision:** Link in tiers A (sink in handler span), B (handler reaches the sink's method by a one-hop call edge), C (route + param). Output confidence. Tier B is the main path on Spring.
- **Why:** Spring layers controller → service. The sink is usually outside the handler, so Tier A alone misses most pairs.
- **Rejected:** A single boolean rule (line containment only).
- **Resolved (contract freeze):** Tier B keys off a one-hop call edge from the route-map parser, carried on the record as `reached_via`. It does not use a cross-file taint trace. Semgrep OSS taint is intraprocedural, so it cannot supply one.
- **Rejected for Tier B:** Semgrep Pro interprocedural taint (paid, setup risk at kickoff). LLM-inferred links as the primary path (allowed only as an advisory fallback, lowest confidence, never a clean Confirmed).
- **Open:** Check call-edge extraction against the real app's layering: hop depth, interface-to-implementation, param-to-argument mapping. `[TODO: confirm at kickoff]`

## D-08 Deterministic core, AI advisory

- **Decision:** Oracles decide every runtime verdict. Correlation is deterministic. AI never moves a scored metric.
- **Why:** The metrics punish eager or hallucinated links. PoC-Gym reports LLMs falsely declaring exploit success. The oracle is the arbiter.
- **Rejected:** An LLM judging exploit success or creating links.

| AI use | Tier | Rule |
|---|---|---|
| Fix text per confirmed issue (B-4) | Do first | No metric risk |
| Link explanations from deterministic reasons (B-3) | Do first | No metric risk |
| SAST false-positive triage (B-2) | Advisory | May demote confidence, never delete. A Tier A/B match overrides it. |
| Taint-spec inference (IRIS-style) | Gated / stretch | Raises recall on custom wrappers |
| Auto-verify Code-only (B-1) | Gated / stretch | The oracle decides success, not the LLM |
| Fuzzy correlation fallback | Gated / stretch | Only after A–C fail. Lowest confidence. |

## D-09 Schema first, aligned to grader vocabulary

- **Decision:** Ratify and freeze the internal finding record in hour one. Map `type` and `cwe` to the VulnerableApp grader vocabulary at the benchmark boundary.
- **Why:** Every component depends on it. A vocabulary mismatch makes grader matches miss.
- **Rejected:** Letting each scanner keep its own format and converting late.
- **Changed:** Earlier drafts called this a frozen JSON "common format". It is now the internal record only. SARIF is the interchange format at the edges (D-13).

## D-10 CLI-only delivery

- **Decision:** A Python CLI with a printed report. No UI, API, server or login.
- **Why:** The PRD accepts a CLI report. FR-10 allows a command line.
- **Rejected:** A web page or REST API.

## D-11 Four vulnerability types

- **Decision:** Commit to SQLi (CWE-89), XSS (CWE-79), command injection (CWE-78) and open redirect (CWE-601). Path traversal (CWE-22) is stretch.
- **Why:** The PRD says a few types done well beat many done badly. Four is the minimum and includes SQLi and XSS.
- **Rejected:** All six types.

## D-12 Code-only path on VulnerableApp

- **Decision:** Use VulnerableApp's cryptographic-failures or JWT module as the Code-only stand-in.
- **Why:** VulnerableApp has no hard-coded-secrets module. The FR-7 three-label path still needs to demo.
- **Rejected:** Planting secrets in VulnerableApp ourselves. It changes the benchmark.
- **Open:** Crypto or JWT module. `[TODO: confirm]`

## D-13 SARIF at boundaries, rich record internally

- **Decision:** SARIF 2.1.0 is the interchange and output format. We ingest Semgrep findings as SARIF. We export correlated results as SARIF for B-6, and CI mode fails the build on Confirmed high-severity issues. Inside the engine, every component uses the internal finding record. Mapping happens only at ingest and export. The export is lossy. The record is the source of truth.
- **Why not SARIF internally:** SARIF is file/line oriented. Correlation needs fields it has no general place for: a DAST finding's URL, method, parameter, payload and runtime evidence; our label, confidence tier and risk score; the Semgrep `taint_trace`; and the `reached_via` call edges that Tier B matches on. Holding these in `properties` bags inside the engine would make the scored core depend on untyped extension data.
- **Rejected:** SARIF as the internal format. Also rejected: no SARIF at all, which loses Semgrep's standard output and B-6.
- **Note on the rationale:** SARIF 2.1.0 does define `webRequest` / `webResponse` objects and `codeFlows` on results `[verify against the 2.1.0 spec]`. So "no native place" is not strictly true for URL, method, payload or trace. The decision still holds: these fields are rarely used by consumers, and SARIF has no field for label, confidence or the two-source merge. Whether the export should use `webRequest` and `codeFlows` in addition to `properties`: `[TODO: open question]`
- **Boundary formats:** Semgrep SARIF in. SARIF out. VulnerableApp grader JSON out, which is separate and not SARIF.

## D-14 Separate Docker network and volume for our log store

- **Decision:** Our run logs and findings live in a PostgreSQL container (official `postgres` image). It runs on our own Docker network and stores data in our own named volume. The target app runs on its own Compose network. Our scanner reaches the target over the host at `localhost:<port>`, never by joining the target's network. Proposed names: network `sastdast-net`, volume `sastdast-pgdata`, service `sastdast-postgres`. Ratify in hour one.
- **Why:**
  - The target cannot write to or read our log and evidence store.
  - Tearing down or resetting the target does not touch our data.
  - It keeps to the rule of scanning only the test app on localhost. Our DB is never exposed to or reachable from the target.
  - Persistence gives FR-6 dedupe across runs and B-5 scan comparison.
- **Rejected:**
  - Joining the target's network. That mixes our state with the target and lets the target reach our DB.
  - A shared volume with the target.
  - No persistent store. Then FR-6 re-run dedupe and B-5 have nothing to compare against.
- **Note:** Persistence is our tool's own state. It does not change the localhost-only rule or CLI-only delivery (D-10).
- **Resolved (placement):** The DAST-capable CLI runs on the host, so `localhost` is the host and the target app. Postgres stays in a container and publishes its port on `127.0.0.1` only. Because `sastdast-net` is internal, and Docker does not publish ports for containers only on internal networks, Postgres also joins a second bridge network, `sastdast-hostport`, used only for that loopback port. The containerised CLI remains for consuming record files.
- **Rejected:** `host.docker.internal`. The target would have to be reachable beyond host loopback, which breaks the localhost-only assumption.

## D-15 Code in common/ is canonical; contract logic lives there too

- **Decision:** The record model in `common/` is the source of truth. [finding-schema.md](finding-schema.md) describes it and points to it. When they disagree, the code wins. `common/` also holds the contract logic both halves must compute identically: `normalise_route(url, route_map)` and `dedupe_key(record)`. Changes to contract logic are stop-the-world, like the schema.
- **Why:** A prose schema drifts from code as soon as one side is edited. If A and B normalise routes differently, Tier A/B matching and dedupe disagree without any error.
- **Rejected:** The doc as canonical. Each half writing its own normaliser.
- **Note:** This is a named exception to "the halves never meet through shared code" ([repo-structure.md](repo-structure.md)). No shared component code. Only contract code.
- **Open:** Model style (dataclass / TypedDict / Pydantic). `[TODO: decide]`

## D-16 Separate route_map() entry; ScanTarget stays immutable

- **Decision:** Producer entries are `route_map(target) -> RouteMap`, `run_sast(target, route_map) -> [Record]` and `run_dast(target, route_map) -> [Record]`. `ScanTarget` holds `source_path`, `base_url`, `run_id` and `framework`. The CLI computes the map once and passes it to both scanners and the engine.
- **Why:** The map is needed by DAST seeding, by SAST (`reached_via`) and by the engine. `ScanTarget` is input config. The map is derived output. Keeping them apart avoids mutating the target after construction.
- **Rejected:** One `run(target)` for all producers (cannot return the map). The map as a field on `ScanTarget`.

## D-17 Dedupe keys, merge rule and severity

- **Decision:**
  - `dedupe_key`: `(cwe, file, line)` when present, else `(cwe, route, method, param)`. Routes are normalised to templates first.
  - App-wide header findings collapse to `(cwe, header_name)`.
  - Merge rule: a newly linked pair searches stored issues by both keys and merges into any match, including a stored Runtime-only issue.
  - `severity` is the scanner's claim, filled by the producer and shown in the report (FR-1). `risk_score` is our ranking, filled by the engine (FR-9). Raw scanner severity also goes in `evidence`.
  - `method` is a real field. `wasc_id` is an optional passthrough for the grader, unused internally.
- **Why:** One key alone splits a bug across runs when it moves from Runtime-only to Confirmed, which breaks FR-6. `method` separates two bugs on one route and CWE.
- **Rejected:** A single `(cwe, file, line)` key. Engine-only severity (fails FR-1).
- **Open:** Does the answer key count missing headers per URL or per app? `[TODO: confirm at kickoff]`. Collapse for now. Flip if needed.
