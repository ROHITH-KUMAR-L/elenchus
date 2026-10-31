# Architecture

Status: target-state description. The stages below are a plan. Nothing here is claimed as built, tested or measured by this revision. How the code in the repo relates to this design: [implementation-plan.md](implementation-plan.md).

## Core idea

Static-guided dynamic testing. Static analysis produces hypotheses. Dynamic testing probes them.

A directed hypothesis keeps its `hypothesis_id` through the probe and into the evidence. A directed hit is linked by lineage, not by matching afterwards.

What this does and does not buy:

- A firing probe proves that route, param and CWE are exploitable.
- It does not prove which sink on that route is the cause.
- Wrong links therefore move from bad matching to same-route sink ambiguity. This design marks that ambiguity. It does not remove it.

## Run model (local mode)

- The target app runs from its own Docker Compose on our machine: the organisers' app at judging, OWASP VulnerableApp for practice.
- Our tool is a Python CLI. It reads the target's source folder and scans the target on `localhost`.
- DAST targets `localhost` only. Any other host is disqualification.
- One target framework per run.
- Our own stack (CLI + Postgres) runs separately from the target. See [Topology](#topology).

## Pipeline

```mermaid
flowchart TD
    src[Target source]
    app["Target app (localhost)"]
    idx["1 Code index (tree-sitter-java): routes, param bindings, call graph, sink inventory"]
    pre["0 Preflight: context path, baseline per route, coverage report"]
    sta["2 Static: own sink finder, secrets/crypto pass, call graph walked backward to routes"]
    semgrep["Semgrep adapter (optional, off by default)"]
    hyp["3 Hypotheses: directed and sweep"]
    probe["4 Probe engine (httpx): baseline gate, differential oracles, canary, replay log"]
    corr["5 Correlation: evidence, link_status, dedupe"]
    ver["6 Verify: status for findings with no oracle hit"]
    out["7 Output: labels, scoring, Postgres, CLI, SARIF"]
    src --> idx
    idx -- route table --> pre
    pre -- baseline requests --> app
    idx --> sta
    src --> sta
    semgrep -.-> sta
    sta --> hyp
    pre -- baseline status per route --> probe
    hyp --> probe
    probe -- probes --> app
    probe --> corr
    hyp --> corr
    corr --> ver
    ver --> out
    out --> graded["Primary report + graded export"]
    out --> supp["Suppressed file"]
```

Stage numbers are labels. The baseline step in stage 0 needs the route table from stage 1, so inside a scan the route table is built first `[proposed]`.

| Stage | Owner of the verdict | Output |
|---|---|---|
| 0 Preflight | Own code | Coverage report, baseline status per route |
| 1 Code index | Own code | Route table, param bindings, call graph, sink inventory |
| 2 Static | Own code | `(route, CWE, sink_id, call_path)` per finding, plus secrets and crypto findings |
| 3 Hypotheses | Own code | Directed and sweep hypotheses |
| 4 Probe engine | Own oracles | Probe records with `hypothesis_id` and `ORACLE` evidence |
| 5 Correlation | Own code, deterministic | Linked issues with `link_status` and confidence |
| 6 Verify | Own code, deterministic | `status` for every finding with no oracle hit |
| 7 Output | Own code | Labels, scores, Postgres rows, report, SARIF |

### Stage 0: Preflight

| Item | Level | Notes |
|---|---|---|
| Read the context path | Must | `[TODO: confirm at kickoff: source of the value]` |
| One baseline request per mapped route | Must | Record 404, 401, 403, 400 and other statuses |
| Coverage report | Must | Routes mapped, reached, blocked |
| Source-revision check | Best-effort | Works only if the app exposes git info, e.g. `/actuator/info` |
| `/actuator/mappings`, `/v3/api-docs` route discovery | Best-effort | Often not exposed |
| Auth and CSRF detection | Best-effort | |

None of the best-effort items is part of the spine.

### Stage 1: Code index

Own code, tree-sitter-java.

- Route table: route template, method, handler file, function, line span.
- Param bindings: name, location, Java type.
- Call graph, with dependency-injection and interface-to-implementation cases resolved where simple.
- Sink inventory.
- Unresolved calls are flagged. They are never dropped.

### Stage 2: Static (Must)

- Own sink finder: tree-sitter plus a per-CWE YAML sink catalogue. It matches on call name and receiver type. No dataflow. Output: sink locations with `sink_id`.
- Own secrets and crypto pass: regex and entropy rules for hard-coded secrets (CWE-798), call-name rules for weak hashes and ciphers. Rules live in YAML.
- The call graph is walked backward from each sink to its entry routes. Output per finding: `(route, CWE, sink_id, call_path)`.

This gives route and call path. It does not say which param reaches the sink. The static stage never claims a param.

Semgrep is not part of the pipeline. It is an optional adapter, off by default, enabled by the config flag `semgrep.enabled`. Uses:

| Use | Purpose |
|---|---|
| Fallback sink source | For a non-Java target, until the own finder has an adapter |
| Cross-check | Sinks that both tools flag are marked corroborated |
| Benchmark yardstick | Run offline, outside the pipeline |

The pipeline and its tests must pass with Semgrep not installed.

Own flow engine: Could. It would narrow `candidate_params` from all to the specific param. Promotion gate: it matches Semgrep's 35 of 45 on VulnerableApp, with Semgrep run offline as the yardstick.

Receiver-type matching needs the type information in the code index. Calls whose receiver type does not resolve are flagged, not dropped `[TODO: define the fallback match]`.

### Stage 3: Hypotheses

| Kind | Content | Purpose |
|---|---|---|
| Directed | `(route, CWE, sink_id, call_path)` with `candidate_params` = all params of the route | The probe tries each param. The oracle shows which one fires. |
| Sweep | Every param by every supported class | Bugs static analysis missed |

### Stage 4: Probe engine

Own code, httpx.

| Part | Behaviour |
|---|---|
| Typed seeds | Valid values built from the index types. AI repair is Should. |
| Baseline gate | Attack a param only if its baseline returns the expected status. Otherwise record `blocked_by_validation`. That maps to `status: blocked` `[proposed]`. |
| Canary id | Unique id in every payload |
| Probe header | `X-Elenchus-Probe` on every request |
| Replay log | Full request and response for every probe |
| Header and cookie checks | Own code, about 30 lines. Covers the planted runtime-only class. Needs no correlation. |
| Session manager | Should |
| App-log tail | Could. Never in judging mode. |

Oracles are differential: each compares the probe response with the baseline.

| Class | Oracle |
|---|---|
| SQL injection | Error signature, boolean pair, or timing with repeats |
| XSS | Content type and reflection context: canary reflected unescaped in an HTML context |
| Command injection | Timing with repeats |
| Path traversal | File-content marker |
| Open redirect | `Location` header host |

ZAP is an optional corroborating passive pass for the runtime-only bucket. It never owns a verdict. It is off the critical path and off in judging mode.

### Stage 5: Correlation

Evidence types: `PATH`, `ORACLE`, `TRACE`, `FAMILY`. Definitions in [finding-schema.md](finding-schema.md#linking-and-ambiguity). `TRACE` exists only when the optional log tail runs. It is not available in judging mode.

After an oracle fires, hypotheses are grouped by `(route, param, CWE)`.

| Group size | `link_status` | Result |
|---|---|---|
| One | `unique` | Linked by lineage |
| More than one | `ambiguous` | Lower confidence. All candidate sinks attached as `alternatives`. One primary chosen. |

- Primary rule `[proposed: more specific catalogue match first, then shorter call path, then source order; Semgrep corroboration counts only if the adapter ran]`. A match on receiver type and call name is more specific than a match on call name alone `[proposed meaning]`.
- `TRACE` resolves ambiguity when present.
- Sweep hits (oracle fired, no directed hypothesis): see [Back-guided static search](#back-guided-static-search).
- Confidence is a deterministic function of the evidence present. Reasons are stored. Weights live in config.
- `sink_id` for the Must set is `(file, enclosing_method, start_line, start_col)`. Refining it to `(method, call-site ordinal, arg index)` is Could.
- Dedupe key is `(sink_id, cwe)` `[proposed]`. The resolved param is an attribute. Several firing params on one sink are several evidence entries on one issue.
- One sink reached from several routes is one issue with several `entry_paths`. A config flag decides how the export counts it.

### Back-guided static search

Scope: runtime-only hits from the broad sweep. The oracle fired and no directed hypothesis exists.

1. Start at the hit route's handler in the code index.
2. Walk the call graph forward from the handler.
3. Look for a sink of the same CWE in the sink inventory.
4. A sink is found: attach it as `PATH` evidence. Confidence is lower than for a directed link. Mark the link `link_origin: sweep_derived`. One sink gives `link_status: unique`. Several give `ambiguous`, with alternatives and the primary rule.
5. No sink is found: the finding stays Runtime-only. Set `unlinked_reason`.

Rules:

- Header and cookie findings are never force-linked. They are not searched. They stay Runtime-only.
- The sweep hit supplies the resolved `param`. The found sink supplies `sink_id`, so the dedupe key `(sink_id, cwe)` merges the hit with any static finding for that sink.
- A sweep-derived link never overrides a directed link on the same issue `[proposed]`.
- Confidence reasons record that the link is sweep-derived.

Open point: with the same catalogue and call graph, a sink reachable from the handler already has a directed hypothesis from stage 2. The search adds value only where it uses something stage 2 did not. `[proposed: relaxed matching, call name alone when the receiver type is unresolved, and a walk through calls flagged as unresolved]` `[TODO: decide]`. With the strict rules it will rarely find anything new.

### Stage 6: Verify and negative evidence

Every static finding without an oracle hit gets exactly one status.

| `status` | Condition | Report |
|---|---|---|
| `tested_negative` | Baseline valid for every candidate param, every candidate param probed, all payload families for the CWE tried within budget | Suppressed (PRD bonus B-2) |
| `no_http_path` | No route reaches the sink | Primary report, Code-only, reason shown |
| `blocked` | Baseline gate failed | Primary report, Code-only |
| `untested` | Not reached | Primary report, Code-only |

- Secrets and crypto findings (CWE-798 and similar) are Code-only by nature. They are never labelled `no_http_path`.
- `no_http_path` for injection CWEs: suppress or keep `[TODO: decide]`. Flag `export.suppress_no_http_path`, default false.
- Tradeoff: suppression cuts false alarms. It lowers code-detection recall if the probe missed a real bug. `[TODO: choose the default by running VulnerableApp with and without suppression]`

### Stage 7: Output

- Labels: Confirmed, Code-only, Runtime-only.
- Scoring from config: CWE severity table, exploit factor, evidence-based link factor.
- Postgres, CLI report, SARIF at the boundary, VulnerableApp benchmark adapter.
- Measurement: a hand-made expected-pairs file for VulnerableApp (about 15 minutes of work). Each pair: route, param, CWE, sink file, sink line. `[proposed path: common/fixtures/expected_pairs/vulnerableapp.yaml]`. It measures correct-link and wrong-link rates, because the grader scores SAST and DAST separately. It is used for measurement only and never feeds scanner logic. Replace or extend it with the organisers' answer key at kickoff.

### Graded export and suppressed file

| Output | Contents |
|---|---|
| Primary report and graded export | Every finding except `suppressed`. |
| Suppressed file | `tested_negative` findings, each with its reason. |
| Postgres | Everything, including suppressed findings. |

Config flag `export.include_suppressed`, default false, merges the suppressed findings into the graded export.

## Judging mode

The organisers run the target at judging. A separate config profile applies.

| Rule | Value |
|---|---|
| Log tail | Off |
| Target restarts | None |
| Config | Zero. Detect base URL, context path and routes. `[TODO: how base URL is detected on localhost]` |
| Command | One |
| Time budget per stage | `[TODO: set values]` |
| AI | Off, or call-capped with a deterministic fallback |
| ZAP | Off |
| Semgrep | Off |
| `TRACE` evidence | Unavailable. Ambiguous links stay ambiguous. |
| Total runtime target | Under 5 minutes |

Everything is detected. Nothing is assumed.

## AI advisor (optional side channel)

Use it only where the task is fuzzy, the output is machine-checkable and a wrong answer is caught. Hard rules: [AGENTS.md](../AGENTS.md).

| Task | Check on the output | Level |
|---|---|---|
| Propose source, sink and sanitiser specs for custom wrappers | Must name real symbols | `[TODO: tier]` |
| Generate seeds from DTOs | Baseline must pass. At most 3 repairs. | Should |
| Propose payload variants when blocked | Oracle decides. Strict budget. | Could |
| Judge `tested_negative` findings | Demote only, with a written reason | Should |
| Write fix text (B-4) | Advisory | `[TODO: tier]` |

The pipeline passes its tests with AI off. AI is measured by running VulnerableApp with and without it and reporting the recall and link difference.

## Residual flaws

| Flaw | Effect | Mitigation |
|---|---|---|
| Same-route sink ambiguity | `TRACE` is unavailable at judging, so some links stay ambiguous | Mark `ambiguous`, attach alternatives. Measure how often it happens on VulnerableApp. |
| A real third sink that was never found | The proof links to the wrong hypothesis with misleading confidence | Only `TRACE` catches this |
| Second-order bugs (stored XSS) | Need a write/read route-pair config, or stay unlinked | `injected_route` and `observed_route` fields. Route-pair config is Could. |
| IDOR and business logic | No oracle | None in this design |
| Blind SSRF and XXE | Need out-of-band callbacks. Localhost-only scanning limits this. | None in this design |
| Index gaps | Unresolved calls, Lombok or generated code, reflection | Flag unresolved calls. Never drop them. |
| Sink catalogue quality | Recall depends on the quality of the sink catalogue. Custom wrappers are missed unless the catalogue or an AI spec proposal covers them. | Extend the catalogue. AI spec proposals (Should or Could, `[TODO: tier]`). Measure on VulnerableApp. |
| Non-Java target | Stages 1 and 2 need a new adapter. The rest is unchanged. | Adapter boundary. The optional Semgrep adapter can supply sinks as a fallback. |

## Components

| Component | Framework-specific? | Role |
|---|---|---|
| Code index | Yes | Stage 1. tree-sitter-java. |
| Static stage | Yes | Stage 2. Own sink finder, own secrets and crypto pass, call-graph walk. |
| Semgrep adapter | Optional | Off by default (`semgrep.enabled`). Fallback sink source, cross-check, benchmark yardstick. |
| Preflight | No | Stage 0 |
| Hypothesis builder | No | Stage 3 |
| Probe engine | No | Stage 4. httpx. Oracles, canary, replay log. |
| Correlation + verify | No | Stages 5 and 6. Deterministic. |
| Output | No | Stage 7. Scoring, Postgres, CLI, SARIF, benchmark adapter. |
| AI advisor | No | Optional. Advisory only. |

| Adapter | Status | Route annotations | Param annotations |
|---|---|---|---|
| Java / Spring MVC | Primary | `@RestController` / `@Controller`, class `@RequestMapping`, method `@GetMapping` / `@PostMapping` / `@RequestMapping` | `@RequestParam`, `@PathVariable` |
| Java / JAX-RS | Secondary | Class + method `@Path`, `@GET` / `@POST` | `@QueryParam`, `@PathParam` |

The route table must handle dynamic segments (`/x/{id}` matched against `/x/5`) and class-level base paths. It must read annotation shapes, not names from the test app.

SARIF appears only at the edges: SARIF in from the optional Semgrep adapter, correlated SARIF out. Everything between uses the internal finding record ([finding-schema.md](finding-schema.md)).

## Topology

Our stack and the target app are separate. They share no Docker network and no volume. The only bridge is the scanner's HTTP calls to `localhost:<port>`.

```mermaid
flowchart LR
    subgraph host[Host machine]
        cli["CLI tool (on host)"]
        subgraph ours["sastdast-net (internal)"]
            pg[("sastdast-postgres")]
            vol[/"volume: sastdast-pgdata"/]
            pg --- vol
        end
        cli -- "127.0.0.1 only" --> pg
        port(("localhost:port"))
        subgraph theirs["Target's own network (own Docker Compose)"]
            target["Target app (organisers' or VulnerableApp)"]
        end
        cli -- HTTP, probe engine only --> port
        port -- published port --> target
    end
```

| Item | Proposed name | Purpose |
|---|---|---|
| Network | `sastdast-net` | Our services only. The target never joins it. |
| Volume | `sastdast-pgdata` | Postgres data. Survives target teardown and reset. |
| Loopback bridge | `sastdast-hostport` | Enables the database's loopback-only host port. |
| Service | `postgres` | Official `postgres:17-alpine` image. |

The Compose file is [infra/compose.yaml](../infra/compose.yaml). Its database port is bound only to `127.0.0.1`.

What the store holds:

| Data | Used for |
|---|---|
| Scan runs (`run_id`) | Cross-run identity |
| Raw per-stage findings | Audit, re-correlation |
| Correlated issues, including suppressed | Report, FR-6 dedupe, B-5 comparison |
| Evidence and replay-log references | FR-8 issue detail |
| Benchmark results | Self-scoring history |

Rules:

- The probe engine reaches the target over the host at `localhost:<port>`. It never joins the target's network.
- Postgres is not reachable from the target. It is not exposed beyond our network.
- The store holds our tool's own state. It does not change the localhost-only rule or CLI-only delivery.
- The CLI runs on the host (D-14). If ZAP runs, it runs on the host or in host-network mode with its API on `127.0.0.1`. It never joins the target's Docker network.

Credentials handling for Postgres: `[TODO]`. Never commit them.

## End-to-end workflow

1. Start Postgres. `[TODO: exact command]`
2. Start the target app with its own Docker Compose on `localhost`.
3. Run the CLI with the source folder and the localhost URL. A new `run_id` is recorded. `[TODO: exact CLI]`
4. Build the code index.
5. Run preflight. Write the coverage report.
6. Run the static stage (own sink finder and secrets/crypto pass). Build hypotheses.
7. Probe. Write the replay log.
8. Correlate and verify.
9. Write Postgres rows, the primary report, the graded export and the suppressed file.

## Self-scoring harness (VulnerableApp)

- VulnerableApp ships a grader at `POST /VulnerableApp/scanner/benchmark`.
- It scores SAST and DAST findings separately against its answer key. It writes a coverage / missed / unmatched report.
- It does not grade correlation. The expected-pairs file in stage 7 measures link quality.
- Body shapes and vocabulary: [finding-schema.md](finding-schema.md).
- The grader takes its own JSON, not our SARIF export.
- Grader results are stored in our Postgres for comparison across runs.
- VulnerableApp has no hard-coded-secrets module. The crypto or JWT module stands in for the Code-only path.
