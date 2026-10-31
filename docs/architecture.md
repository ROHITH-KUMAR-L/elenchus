# Architecture

Status: plan. Nothing is built.

## Run model (local mode)

- The target app runs from its own Docker Compose on our machine: the organisers' app at judging, OWASP VulnerableApp for practice.
- Our tool is a Python CLI. It reads the target's source folder and scans the target on `localhost`.
- DAST targets `localhost` only. Any other host is disqualification.
- One target framework per run.
- Our own stack (CLI + Postgres) runs separately from the target. See [Infrastructure (our stack)](#infrastructure-our-stack).

## Components

| Component | Framework-specific? | Role |
|---|---|---|
| SAST adapter | Yes | Runs Semgrep taint rules and a secrets/crypto pass for one framework. Semgrep output is read as SARIF. |
| Route-map adapter | Yes | Parses source into `route template → {file, handler, line_start, line_end, params}`. |
| DAST runner | No | Drives OWASP ZAP via the Python client or Automation Framework YAML. Seeds ZAP with route-map URLs. Active scan for injection, passive scan for headers. |
| Oracles | No | Deterministic HTTP checks that decide each runtime verdict. |
| Normaliser | No | Maps Semgrep SARIF and ZAP alerts to the internal finding record, with grader vocabulary. |
| Correlation + merge | No | Tiered linking, labels, dedupe across runs, risk score. |
| Run store | No | Our Postgres. Runs, raw findings, issues, evidence, benchmark results. Backs FR-6 dedupe and B-5 comparison. |
| Report | No | Prioritised CLI report. SARIF export and CI exit code (B-6). |
| Grader client | No | Sends findings to the VulnerableApp grader in its own JSON. Practice only. |
| AI helpers | No | Advisory only: fix text, link explanations, false-positive demotion. |

Adapter interface: two operations per framework, `sast(source_dir)` and `route_map(source_dir)`. `sast` returns internal finding records. Exact signatures: `[TODO: ratify in hour one]`

| Adapter | Status | Route annotations | Param annotations |
|---|---|---|---|
| Java / Spring MVC | Primary | `@RestController` / `@Controller`, class `@RequestMapping`, method `@GetMapping` / `@PostMapping` / `@RequestMapping` | `@RequestParam`, `@PathVariable` |
| Java / JAX-RS | Secondary | Class + method `@Path`, `@GET` / `@POST` | `@QueryParam`, `@PathParam` |

Parser: tree-sitter-java or javalang. `[TODO: confirm at kickoff]`

The route map must handle dynamic segments (`/x/{id}` matched against `/x/5`) and class-level base paths. It must read annotation shapes, not names from the test app.

## Data flow

SARIF appears only at the edges. Everything between them uses the internal finding record ([finding-schema.md](finding-schema.md)).

```
target source --> Semgrep (taint + secrets/crypto) --[SARIF in]--+
target source --> route-map adapter ----------------------+      |
                     | (seed URLs)                        |      v
                     v                                    |   normaliser
localhost app <-- ZAP active + passive                    |      |
                     | alerts                             |      |
                     v                                    |      |
                  oracles (verdict) ----------------------|----->|
                                                          |      v
                                                          | internal finding record
                                                          |      |
                                                          v      v
                                              correlation + merge <--> run store (Postgres)
                                                          |
                    +-------------------------------------+-------------------+
                    v                                     v                   v
          prioritised CLI report               [SARIF out] (B-6, CI)   grader JSON
                                                                       (VulnerableApp only)
```

Secrets/crypto pass output format (SARIF or tool JSON): `[TODO: confirm with tool choice]`

## Correlation design

Output is a confidence tier, not a boolean. CWE must match in every tier. Param match is the main guard for the <5% wrong-link target.

| Tier | Rule | Confidence | Notes |
|---|---|---|---|
| A | SAST sink line inside the DAST route's handler span, same param | Highest | Rare on Spring: the sink usually sits in a service class. |
| B | Taint **source** end of the SAST trace inside the handler span, sink anywhere | High | **Main path on Spring.** Controller → service layering puts the sink in another file. |
| C | Route + param match only, no line link | Low | Linked but flagged. |

- No SAST partner: Runtime-only.
- No DAST partner: Code-only.
- Merge and dedupe on `(cwe, file, line)` across runs via `run_id`.
- Sort: Confirmed first, then `risk_score` = f(severity, exploit ease, confidence).

Tier B depends on a source-to-sink trace that spans controller and service. Semgrep OSS taint is intraprocedural only. Cross-file taint is a Semgrep Pro feature. How we get a cross-file trace is unresolved: `[TODO: open question, see decisions.md D-07]`

Dedupe key for Runtime-only findings (no `file`/`line`): `[TODO: confirm]`

## Oracles

| Type | Oracle |
|---|---|
| SQLi | DB error string, or time delay |
| XSS | Reflected unescaped marker |
| Command injection | Response time delay |
| Open redirect | `Location` header host |

Whether the oracle replays every ZAP alert or only checks ZAP's own evidence: `[TODO: confirm]`

## Infrastructure (our stack)

Our stack and the target app are separate. They share no Docker network and no volume. The only bridge is the scanner's HTTP calls to `localhost:<port>`.

```
+----------------------------- host machine -------------------------------+
|                                                                          |
|  sastdast-net [proposed]               target's own network              |
|  +--------------------------------+    (target's own Docker Compose)     |
|  | sastdast-postgres [proposed]   |    +----------------------------+    |
|  |   volume: sastdast-pgdata      |    | target app                 |    |
|  |            [proposed]          |    | (organisers' or            |    |
|  | CLI tool [placement: TODO]     |    |  VulnerableApp)            |    |
|  +---------------+----------------+    +-------------+--------------+    |
|                  |                                   |                   |
|                  |  HTTP to localhost:<port>         | published port    |
|                  +---------------> host <------------+                   |
|                                                                          |
+--------------------------------------------------------------------------+
```

| Item | Proposed name | Purpose |
|---|---|---|
| Network | `sastdast-net` | Our services only. The target never joins it. |
| Volume | `sastdast-pgdata` | Postgres data. Survives target teardown and reset. |
| Service | `sastdast-postgres` | Official `postgres` image. Version `[TODO]`. |

Names are proposals. Ratify in hour one. No compose file or SQL is written yet.

What the store holds:

| Data | Used for |
|---|---|
| Scan runs (`run_id`) | Cross-run identity |
| Raw per-scanner findings | Audit, re-correlation |
| Correlated issues | Report, FR-6 dedupe |
| Evidence | FR-8 issue detail |
| Benchmark results | Self-scoring history |

Rules:

- Our scanner reaches the target over the host at `localhost:<port>`. It never joins the target's network.
- Postgres is not reachable from the target. It is not exposed beyond our network.
- The store holds our tool's own state. It does not change the localhost-only rule or CLI-only delivery.

Open: if the CLI or ZAP runs as a container on `sastdast-net`, `localhost` inside it is the container, not the host. Reaching the host then needs another hostname. If the CLI runs on the host instead, Postgres must publish a port to the host loopback. Placement of the CLI and ZAP: `[TODO: open question]`

Credentials handling for Postgres: `[TODO]`. Never commit them.

## End-to-end workflow

1. Start our stack (Postgres on `sastdast-net`). `[TODO: exact command]`
2. Start the target app with its own Docker Compose on `localhost`.
3. Run the CLI with the source folder and the localhost URL. A new `run_id` is recorded. `[TODO: exact CLI]`
4. Route-map adapter builds the route map.
5. SAST adapter runs Semgrep and the secrets/crypto pass. Semgrep SARIF is ingested.
6. ZAP scans the localhost app, seeded from the route map.
7. Oracles check runtime findings.
8. Normaliser writes all findings as internal records. Raw findings go to the store.
9. Correlation links, labels, merges against stored issues, and scores.
10. CLI prints the prioritised list. Issue detail covers FR-8 fields. Optional SARIF export.

## Self-scoring harness (VulnerableApp)

- VulnerableApp ships a grader at `POST /VulnerableApp/scanner/benchmark`.
- It scores SAST and DAST findings separately against its answer key. It writes a coverage / missed / unmatched report.
- It does not grade correlation. We measure link quality ourselves.
- Body shapes and vocabulary: [finding-schema.md](finding-schema.md).
- The grader takes its own JSON, not our SARIF export.
- Grader results are stored in our Postgres for comparison across runs.
- VulnerableApp has no hard-coded-secrets module. The crypto or JWT module stands in for the Code-only path.
