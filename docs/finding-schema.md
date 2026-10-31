# Internal finding record (DRAFT contract, revised)

Status: **DRAFT**. This revision describes the target state. The fields marked below are not in `common/record.py` yet. Changing the record is a joint, stop-the-world change ([CONTRIBUTING.md](../CONTRIBUTING.md)).

Every component reads and writes this record. It is framework-agnostic: no Spring or JAX-RS field names.

SARIF 2.1.0 is the interchange format at the edges only: SARIF in from the optional Semgrep adapter, correlated SARIF out (B-6). The record is the source of truth. SARIF is for interop. See [SARIF mapping](#sarif-mapping-ingestexport-lossy).

## Canonical definition

Code in `common/` is canonical. This doc is the human-readable description. When they disagree, the code wins.

[`common/record.py`](../common/record.py) implements the earlier record. The revised fields below are proposed. Updating `common/record.py`, the engine and the fixtures is a joint change `[TODO: schedule]`.

## What changed

| Earlier field or rule | Now |
|---|---|
| `reached_via` (handler span, one hop) | `entry_paths`: `{route, method, hops, call_chain}` |
| `handler_file`, `handler_line_start`, `handler_line_end` | Removed. The route table keeps handler spans. Each `call_chain` item carries `{method, file, line}`, and the handler is the first hop. |
| `param` filled from the route map or a taint source | `candidate_params` (all params of the route) and `param` (resolved by the oracle, nullable) |
| `evidence` object | `evidence` list of `{type, detail}` |
| `confidence` tier A / B / C | A float from 0 to 1, a deterministic function of the evidence present, `link_status` and `link_origin`. Bands and weights live in config ([Config reference](architecture.md#config-reference)). Each factor is stored in `confidence_reasons`. |
| `risk_score` from severity, exploit ease, confidence | Computed from config: CWE severity table, exploit factor, evidence-based link factor |
| Dedupe key `(cwe, file, line)`, else `(cwe, route, method, param)` | `(sink_id, cwe)` `[proposed]`. See [Contract logic](#contract-logic). |
| `taint_trace` from Semgrep | Kept, optional. Null in the Must plan. The own sink finder gives locations only. |
| Tiers A / B / C | Evidence types `PATH`, `ORACLE`, `TRACE`, `FAMILY`, plus `link_status` and `link_origin` |

## Fields

| Field | Type | Meaning | Filled by |
|---|---|---|---|
| `run_id` | string | Scan run. Used for cross-run merge. | All |
| `source` | `"sast"` \| `"dast"` | Which stage produced it. | All |
| `provenance` | `"own"` \| `"semgrep"` \| `"llm"` \| `"zap"` | Which component produced the finding. `semgrep` appears only when the optional adapter ran. | All |
| `corroborated` | boolean \| null | True when the own finder and the Semgrep adapter flag the same sink. Null when the adapter did not run `[proposed field]`. | Static stage |
| `cwe` | integer | CWE number. | Rule metadata; probe class |
| `type` | string | Type name from the grader vocabulary (see below). | Mapping table |
| `route` | string \| null | Normalised URL template. Always from `normalise_route()`. On a static record, set only when exactly one entry path reaches the sink `[proposed]`. | DAST; static stage |
| `method` | string \| null | HTTP method. Same rule as `route`. | DAST; static stage |
| `file` | string \| null | Sink file (SAST). | SAST |
| `line` | integer \| null | Sink line (SAST). | SAST |
| `sink_id` | object \| null | `{file, enclosing_method, start_line, start_col}`. Refined later to `(method, call-site ordinal, arg index)` (Could). Copied onto the probe record from its hypothesis `[proposed]`. | Static stage |
| `entry_paths` | array \| null | Routes that reach the sink. Each: `route`, `method`, `hops` (calls from handler to the sink's method), `call_chain` (list of `{method, file, line}`, the handler is the first hop). One sink reached from several routes is one record with several entry paths. | Static stage, from the call graph |
| `hypothesis_id` | string \| null | Id of the hypothesis that produced the finding. Kept through the probe and into the evidence. Null for findings with no hypothesis (own header checks). | Stage 3 |
| `candidate_params` | array \| null | Params the probe will try. Directed: all params of the route. | Stage 3 |
| `param` | string \| null | Param the oracle fired on. Null until a probe resolves it, and for static-only findings. | Probe engine |
| `param_location` | string \| null | Where the param is bound: `query`, `path`, `header`, `cookie`, `body` `[proposed values]`. | Probe engine, from the index |
| `param_path` | string \| null | Path inside a structured value, e.g. a JSON field `[proposed meaning]`. | Probe engine |
| `payload` | string \| null | Payload that fired. | Probe engine |
| `evidence` | array | List of `{type, detail}`. Types: `PATH`, `ORACLE`, `TRACE`, `FAMILY`. Raw artefacts (code snippet, request, response excerpt, canary id, replay-log reference, raw scanner severity) go inside `detail`. | All |
| `taint_trace` | array \| null | Optional source-to-sink path. Each step: `file`, `line`, `role`. Null in the Must plan. | Own flow engine (Could) |
| `link_status` | `"unique"` \| `"ambiguous"` \| null | How many candidate sinks the link has. Set after an oracle fires. See [Linking](#linking-and-ambiguity). | Correlation |
| `link_origin` | `"directed"` \| `"sweep"` \| `"back_guided"` \| null | How the link was produced. Orthogonal to `link_status`. Both are required once a link exists. | Correlation |
| `ambiguity_group_id` | string \| null | Shared by hypotheses in one `(route, param, CWE)` group of more than one. | Correlation |
| `alternatives` | array \| null | `sink_id` of every other candidate in the group. Exported in the SAST grader payload. Not separate issues in the primary report. | Correlation |
| `candidate_sinks` | array \| null | `sink_id` of each candidate when the back-guided search finds several, or of the sink in a conflict case below the confidence threshold. Hints only. No Confirmed link is made. | Back-guided search; correlation |
| `match_mode` | `"strict"` \| `"relaxed"` \| null | How a sink was matched. `strict` is the default: a catalogue match with a resolved receiver type. `relaxed` means call name alone with the receiver type unresolved. Every back-guided match is `relaxed`. | Static stage; back-guided search |
| `unresolved_hops` | integer \| null | Unresolved calls walked to reach the sink. At most 3. Back-guided search only. | Back-guided search |
| `conflict` | boolean | True when a positive oracle hit overrode `tested_negative`. | Correlation |
| `status` | string \| null | For findings with no oracle hit: `tested_negative`, `no_http_path`, `blocked`, `untested`. See [Statuses](#statuses). | Verify stage |
| `suppressed` | boolean | True for `tested_negative`. Excluded from the primary report and the graded export. | Verify stage |
| `unlinked_reason` | string \| null | Why a finding has no partner. For `blocked`, `untested` and `no_http_path` findings it records the per-param probe outcomes, the `blocked_by_validation` sub-code (`validation`, `auth`, `not_found`, `server_error`, `other`) and the `no_http_path` reason code (`no_callers`, `walk_unresolved`). | Correlation |
| `injected_route` | string \| null | Route that wrote the value (second-order flows). | Probe engine, from route-pair config |
| `observed_route` | string \| null | Route where the value fired. | Probe engine |
| `source_rev` | string \| null | Source revision the scan ran against. Best-effort. | Preflight |
| `severity` | string \| null | Producer's severity claim. Shown in the report (FR-1). | Producer |
| `wasc_id` | integer \| null | Passthrough for the VulnerableApp grader. Not used inside the engine. | ZAP alert, or own mapping |
| `label` | `"Confirmed"` \| `"Code-only"` \| `"Runtime-only"` | FR-7 label. Set by correlation, not by producers. | Correlation |
| `confidence` | number (0 to 1) \| null | Deterministic function of the evidence present, `link_status` and `link_origin`. Bands and weights live in config ([Config reference](architecture.md#config-reference)). | Correlation |
| `confidence_reasons` | array \| null | List of `{factor, delta}`: each factor behind `confidence` and its effect. Written by the engine (Person B). Producers never set it. A contract field added before the freeze. | Correlation |
| `risk_score` | number \| null | Our ranking number. Drives FR-9 ordering. Weights live in config. | Correlation |

`severity` and `risk_score` are two fields. Do not collapse them.

`oracle_flaky` is a key inside an `ORACLE` evidence entry's `detail`, not a record field `[proposed placement]`. It is true when a replay did not reproduce the hit.

## Hypothesis shape

A hypothesis is a pipeline object, not a finding. It lives in `common/` with the record. Same freeze rules.

| Field | Meaning |
|---|---|
| `hypothesis_id` | Stable id `[proposed: hash of kind, route, method, cwe, sink_id]` |
| `kind` | `directed` or `sweep` |
| `route`, `method` | Route under test |
| `cwe` | Class to probe |
| `sink_id`, `call_path` | Directed only. From the static stage. |
| `candidate_params` | Directed: all params of the route. Sweep: one param. |

Directed hypotheses come from static findings. Sweep hypotheses cover every param against every supported class, for bugs static analysis missed. Both sets use this one record type. The probe engine does not care which set a hypothesis came from.

## Other contract shapes

### ScanTarget

Immutable input config. Built once by the CLI.

| Field | Meaning |
|---|---|
| `source_path` | Target source folder |
| `base_url` | Target app on `localhost` |
| `run_id` | This run |
| `framework` | Adapter to use, e.g. Spring MVC `[proposed]` |

### CodeIndex

Derived output of stage 1. Replaces `RouteMap` as the stage-1 output `[proposed; RouteMap becomes the route-table part]`.

| Part | Contents |
|---|---|
| Route table | Route template, method, handler file, function, line span |
| Param bindings | Param name, location, Java type |
| Call graph | Method-to-method edges. Unresolved calls are flagged, never dropped. |
| Sink inventory | Sink call sites with `sink_id` and CWE |

### Stage data

Signatures `[TODO: ratify]`.

| Stage | Output |
|---|---|
| 1 Code index | `CodeIndex` |
| 2 Static | Static findings: records with `source: sast`, `status: untested`, `entry_paths`, no `param` |
| 3 Hypotheses | Hypothesis list |
| 4 Probe | Records with `source: dast`, `hypothesis_id`, resolved `param`, `ORACLE` evidence |
| 5 Back-guided search (optional) | `run_back_guided(target, route_map, runtime_only_findings)`. Person A. Evidence for runtime-only hits. |
| 5 to 6 Correlate, verify | Issues with label, `link_status`, `link_origin`, `status` |

### Contract logic

| Function | Rule |
|---|---|
| `normalise_route(url, route_map) -> template` | Maps a concrete URL (`/orders/5`) to its template (`/orders/{id}`) using the route table. Every `route` value comes from this. Strips the servlet context path `[TODO: decide where the context path found by preflight is stored; today it comes from ScanTarget.base_path]`. |
| `dedupe_key(record)` | `(sink_id, cwe)` `[proposed]`. The resolved `param` is an attribute. Several firing params on one sink are several `evidence` entries on one issue. |

The new key replaces `(sink_id, param)` because `param` is unknown for static-only findings.

Findings with no `sink_id` use a fallback key:

| Finding | Key |
|---|---|
| Secrets | `(cwe, file, line)` |
| Runtime-only injection | `(cwe, normalised_route, method, param)` |
| Header findings | Under `header.count_mode = per_app`: `(cwe, header_name)`. Under `per_url`: `(cwe, header_name, normalised_route)` `[proposed]`. `[TODO: confirm at kickoff against the answer key]` |

### Merge rule

A new probe or static finding searches stored issues by `dedupe_key` and merges into any match. A sink reached from several routes is one issue with several `entry_paths`. Config `export.count_multi_entry` decides how the export counts it `[TODO: confirm at kickoff against the answer key]`.

## Linking and ambiguity

A firing probe proves that route, param and CWE are exploitable. It does not prove which sink on that route is the cause.

`link_status` and `link_origin` are orthogonal. `link_origin` alone would hide ambiguity on sweep links.

| Field | Values | Meaning |
|---|---|---|
| `link_status` | `unique`, `ambiguous` | How many candidate sinks the link has |
| `link_origin` | `directed`, `sweep`, `back_guided` | How the link was produced |

| Case | `link_status` | `link_origin` | Result |
|---|---|---|---|
| One hypothesis in the `(route, param, CWE)` group | `unique` | `directed` | Linked by lineage: `hypothesis_id` carried through the probe |
| More than one hypothesis in the group | `ambiguous` | `directed` | Lower confidence. All candidate sinks attached in `alternatives`. One primary chosen. |
| Sweep hit matches a static finding of the same CWE whose `entry_paths` include the route `[proposed meaning]` | by count | `sweep` | Lower confidence |
| Back-guided search finds exactly one sink | `unique` | `back_guided` | `PATH` evidence. Confidence starts at `backguided.start_confidence` and loses `backguided.hop_penalty` per unresolved hop. Confirmed only at or above `backguided.min_confidence_to_confirm`. |
| Back-guided search finds several sinks | `ambiguous` | `back_guided` | Label stays Runtime-only. `candidate_sinks` hold the hints. No Confirmed link is exported. |
| Back-guided search finds none | null | null | Stays Runtime-only. `unlinked_reason` set. |
| Header, cookie or info-leak finding | null | null | Never searched. Stays Runtime-only. |
| Positive oracle hit on a `tested_negative` sink, reproduces in at least `replay.min_hits` of `replay.count` replays | `ambiguous` | `sweep` | `conflict: true`. Un-suppressed. At or above `backguided.min_confidence_to_confirm`: Confirmed. Below it: Runtime-only, sink listed in `candidate_sinks` as a hint, no Confirmed export. |
| Same hit, does not reproduce | null | null | `tested_negative` kept. `oracle_flaky: true`. Hit stays Runtime-only. |

### Confidence

Confidence is a float from 0 to 1. It is a deterministic function of the evidence present, `link_status` and `link_origin`. `confidence_reasons` records each factor and its delta. The engine writes it. Producers never set it.

Band cut points, back-guided start confidence, hop penalty and the confirm threshold are config. Values: [Config reference](architecture.md#config-reference). The cut points are tuned on `expected_pairs` runs.

A conflict case will usually fall below the confirm threshold. It then exports as Runtime-only with `conflict: true`.

Evidence types `[proposed meanings]`:

| Type | Meaning |
|---|---|
| `PATH` | A call path exists from an entry route to the sink |
| `ORACLE` | A probe oracle fired. Detail holds oracle name, canary id, baseline status, replay-log reference. |
| `TRACE` | The app log shows the payload reaching the sink. Optional. |
| `FAMILY` | The payload family that fired matches the CWE family of the sink |

## Statuses

A finding with no oracle hit gets one status, assigned in this order:

1. An oracle fired: the finding is linked. It has no unconfirmed status.
2. No route reaches the sink: `no_http_path`, with a reason code.
3. Any candidate param is `blocked_by_validation` and no oracle fired: `blocked`.
4. Every candidate param probed, baseline valid, all payload families for the CWE tried within budget: `tested_negative`.
5. Otherwise (budget spent or not attempted): `untested`.

| `status` | Rule | Report |
|---|---|---|
| `tested_negative` | 4 | Suppressed. Kept in Postgres. Excluded from the primary report and the graded export. Written to a separate suppressed file. |
| `no_http_path` | 2 | Primary report, Code-only, reason code shown. Suppressed only if eligible. |
| `blocked` | 3 | Primary report, Code-only |
| `untested` | 5 | Primary report, Code-only |

`blocked_by_validation` is a probe outcome recorded per candidate param when its baseline fails the expected status. Sub-codes: `validation` (400, 422), `auth` (401, 403), `not_found` (404), `server_error` (5xx), `other`. The per-param outcomes and the sub-code go in `unlinked_reason`.

`no_http_path` reason codes: `no_callers` (the backward walk found no caller) and `walk_unresolved` (the walk stopped at an unresolved call).

Only `no_callers` findings in injection CWEs are ever eligible for suppression, under `export.suppress_no_http_path`. `walk_unresolved` findings and secrets/crypto findings (CWE-798 and similar) are never suppressed.

Flags: `export.include_suppressed`, `export.suppress_no_http_path`. Values: [Config reference](architecture.md#config-reference).

## Vocabulary alignment

The VulnerableApp grader (`POST /VulnerableApp/scanner/benchmark`) matches on its own canonical CWE/type vocabulary, defined in its `benchmarks/README.md`. Our `type` and `cwe` values must map onto it, or matches will miss.

| Our class | CWE | Grader `type` string |
|---|---|---|
| SQL injection | 89 | `SQL Injection` |
| XSS | 79 | `Reflected XSS` |
| Command injection | 78 | `Command Injection` |
| Open redirect | 601 | `Open Redirect` |
| Path traversal (Should, M3) | 22 | `Path Traversal` |
| Hard-coded credentials | 798 | `Hard-coded Credentials` |
| Cryptographic failures | 326 or 327 | `Cryptographic Failures` |
| Weak random | 330 | `Weak Random Number Generation` |
| Weak password hashing | 916 | `Weak Password Hashing` |
| Vulnerable JWT | 347 | `Server Side Vulnerable Jwt` |

For the VulnerableApp grader only, internal CWE-78 is translated to grader CWE-77. The internal finding remains CWE-78. See `common/vocabulary.py`.

Grader request bodies, as stated in VulnerableApp's docs:

- DAST: `{ tool, scanType: "DAST", findings: [ {url, type, cwe, wascId} ] }`
- SAST: `{ tool, scanType: "SAST", findings: [ {filePath, line, cwe, type} ] }`

The grader takes its own JSON. It is a third boundary format, separate from our SARIF export. Do not send SARIF to the grader.

## SARIF mapping (ingest/export, lossy)

**Ingest.** Only the optional Semgrep adapter ingests SARIF. Its output becomes static findings with `provenance: semgrep`. The own finders do not use SARIF. `ruleId` and rule metadata give `cwe` and `type`. `locations` give the sink `file` and `line`. Semgrep gives no param and no trace, so `param` and `taint_trace` stay null. The own finders also leave them null.

**Export (B-6).** Each correlated issue becomes one SARIF `result`. Fields with no SARIF home go in `result.properties`. The mapping is lossy. The internal record is the source of truth.

| Internal field | SARIF export location | Loss |
|---|---|---|
| `file`, `line` | `locations[0].physicalLocation` | None |
| `sink_id` | `locations[0]`, plus `partialFingerprints` `[proposed]` | Column kept only in fingerprint |
| `entry_paths`, `hypothesis_id`, `provenance` | `properties` | Ignored by most viewers |
| `alternatives`, `link_status`, `ambiguity_group_id` | `properties`. Alternative sinks also in `relatedLocations` `[proposed]`. | Viewers show only related locations |
| `evidence`, `confidence_reasons`, `corroborated`, `link_origin`, `match_mode`, `unresolved_hops`, `candidate_sinks`, `conflict` | `properties` | Ignored by most viewers |
| `suppressed` | SARIF `suppressions` `[verify against the 2.1.0 spec]` | None if supported |
| `status`, `param`, `payload`, `method`, `route` | `properties` | Ignored by most viewers |
| `severity` | `level` (`error` / `warning` / `note`) | Coarser scale |
| `label`, `confidence`, `risk_score`, `run_id`, `source` | `properties` | Ignored by most viewers |
| `cwe`, `type` | `properties.cwe`, `ruleId`, `message.text`. Rule tags `[TODO: GitHub code-scanning tag format]` | None in file |

The graded export excludes suppressed findings. The suppressed file holds them, one SARIF result each with `suppressions` set `[proposed]`.

Issues with no `file` or `line` (Runtime-only, sweep hits): how to export them in SARIF `[TODO: open question]`. Whether to use SARIF `webRequest` and `webResponse` for `ORACLE` detail `[TODO: open question]`.

CI mode: exit non-zero when any issue is `Confirmed` with high severity. Threshold `[TODO: confirm]`.

## Examples

Illustrative only. File paths, ids and port are placeholders. Most examples use `GET /api/orders/{id}`. The back-guided example uses `GET /api/reports/{id}`.

### Static finding (stage 2 output)

A SQL sink in a service class. The own sink finder matched it by call name and receiver type. The call graph walked backward to one route. No param is known yet.

```json
{
  "run_id": "example-run",
  "source": "sast",
  "provenance": "own",
  "cwe": 89,
  "type": "SQL Injection",
  "route": "/api/orders/{id}",
  "method": "GET",
  "file": "src/main/java/com/example/shop/OrderService.java",
  "line": 88,
  "sink_id": {
    "file": "src/main/java/com/example/shop/OrderService.java",
    "enclosing_method": "OrderService.find",
    "start_line": 88,
    "start_col": 31
  },
  "entry_paths": [
    { "route": "/api/orders/{id}", "method": "GET", "hops": 1,
      "call_chain": [
        { "method": "OrderController.get", "file": "src/main/java/com/example/shop/OrderController.java", "line": 40 },
        { "method": "OrderService.find", "file": "src/main/java/com/example/shop/OrderService.java", "line": 80 }
      ] }
  ],
  "hypothesis_id": "h-3f9a",
  "candidate_params": ["id", "sort"],
  "param": null,
  "param_location": null,
  "param_path": null,
  "payload": null,
  "evidence": [
    { "type": "PATH",
      "detail": { "snippet": "stmt.executeQuery(\"SELECT * FROM orders WHERE id = \" + id)",
                  "catalogue_entry": "[TODO: catalogue id]" } }
  ],
  "taint_trace": null,
  "corroborated": null,
  "severity": "high",
  "status": "untested",
  "suppressed": false,
  "link_status": null,
  "ambiguity_group_id": null,
  "alternatives": null,
  "unlinked_reason": null,
  "injected_route": null,
  "observed_route": null,
  "source_rev": null,
  "wasc_id": null,
  "label": null,
  "confidence": null,
  "confidence_reasons": null,
  "risk_score": null
}
```

### Probe finding (stage 4 output)

The probe engine tried both candidate params. The oracle fired on `id`.

```json
{
  "run_id": "example-run",
  "source": "dast",
  "provenance": "own",
  "cwe": 89,
  "type": "SQL Injection",
  "route": "/api/orders/{id}",
  "method": "GET",
  "file": null,
  "line": null,
  "sink_id": {
    "file": "src/main/java/com/example/shop/OrderService.java",
    "enclosing_method": "OrderService.find",
    "start_line": 88,
    "start_col": 31
  },
  "entry_paths": null,
  "hypothesis_id": "h-3f9a",
  "candidate_params": ["id", "sort"],
  "param": "id",
  "param_location": "path",
  "param_path": null,
  "payload": "1'",
  "evidence": [
    { "type": "ORACLE",
      "detail": { "oracle": "db_error",
                  "canary_id": "elx-7c1e",
                  "baseline_status": 200,
                  "request": "GET http://localhost:[TODO: port]/api/orders/1'",
                  "replay_log": "[TODO: path]" } }
  ],
  "taint_trace": null,
  "severity": null,
  "status": null,
  "suppressed": false,
  "link_status": null,
  "label": null,
  "confidence": null,
  "risk_score": null
}
```

After correlation the two merge into one issue. The group `(/api/orders/{id}, id, 89)` has one hypothesis, so the link is unique:

```json
{
  "label": "Confirmed",
  "link_status": "unique",
  "param": "id",
  "evidence": [
    { "type": "PATH",   "detail": { "call_chain": [
        { "method": "OrderController.get", "file": "src/main/java/com/example/shop/OrderController.java", "line": 40 },
        { "method": "OrderService.find", "file": "src/main/java/com/example/shop/OrderService.java", "line": 80 }
      ] } },
    { "type": "ORACLE", "detail": { "oracle": "db_error", "canary_id": "elx-7c1e" } },
    { "type": "FAMILY", "detail": { "payload_family": "sqli-error", "cwe": 89 } }
  ],
  "confidence": "[TODO: float 0 to 1]",
  "confidence_reasons": [
    { "factor": "oracle_fired", "delta": "[TODO: from config]" },
    { "factor": "one_hypothesis_in_group", "delta": "[TODO: from config]" },
    { "factor": "path_exists", "delta": "[TODO: from config]" }
  ],
  "risk_score": null
}
```

### Ambiguous group

A second SQL sink, `OrderRepository.load`, sits behind the same route. Both sinks produce a hypothesis. The probe fires once, on `id`.

```json
{
  "label": "Confirmed",
  "link_status": "ambiguous",
  "ambiguity_group_id": "g-1",
  "route": "/api/orders/{id}",
  "method": "GET",
  "param": "id",
  "cwe": 89,
  "sink_id": {
    "file": "src/main/java/com/example/shop/OrderService.java",
    "enclosing_method": "OrderService.find",
    "start_line": 88,
    "start_col": 31
  },
  "alternatives": [
    { "file": "src/main/java/com/example/shop/OrderRepository.java",
      "enclosing_method": "OrderRepository.load",
      "start_line": 41,
      "start_col": 20 }
  ],
  "evidence": [
    { "type": "PATH",   "detail": { "hypotheses": ["h-3f9a", "h-81bd"] } },
    { "type": "ORACLE", "detail": { "oracle": "db_error", "canary_id": "elx-7c1e" } },
    { "type": "FAMILY", "detail": { "payload_family": "sqli-error", "cwe": 89 } }
  ],
  "confidence": "[TODO: float 0 to 1]",
  "confidence_reasons": [
    { "factor": "oracle_fired", "delta": "[TODO: from config]" },
    { "factor": "two_hypotheses_in_group", "delta": "[TODO: from config]" },
    { "factor": "primary_by_rule_more_specific_catalogue_match", "delta": "[TODO: from config]" },
    { "factor": "no_trace_evidence", "delta": "[TODO: from config]" }
  ]
}
```

The oracle proves the route and param. It does not say whether line 88 or line 41 is the cause. The primary is chosen by the stated rule. The alternative stays attached.

The alternative sinks go in the SAST grader payload, with the primary, under `export.include_alternatives`. In the primary report they are attributes of the primary issue, not separate issues. `[TODO: measure false alarms and code detection with the flag on and off on VulnerableApp against expected_pairs, then set the default.]`

### Back-guided link

A sweep hit on `GET /api/reports/{id}` had no hypothesis. The handler calls `reportEngine.run(...)`. The receiver type of `reportEngine` is unresolved. The relaxed search matched the call name `run` and found one SQL sink, one unresolved hop away.

```json
{
  "label": "Confirmed",
  "route": "/api/reports/{id}",
  "method": "GET",
  "param": "id",
  "cwe": 89,
  "sink_id": {
    "file": "src/main/java/com/example/shop/ReportQuery.java",
    "enclosing_method": "ReportQuery.run",
    "start_line": 52,
    "start_col": 24
  },
  "link_status": "unique",
  "link_origin": "back_guided",
  "match_mode": "relaxed",
  "unresolved_hops": 1,
  "candidate_sinks": null,
  "evidence": [
    { "type": "PATH",
      "detail": { "call_chain": [
                    { "method": "ReportController.get", "file": "src/main/java/com/example/shop/ReportController.java", "line": 30 },
                    { "method": "reportEngine.run", "file": null, "line": 33 },
                    { "method": "ReportQuery.run", "file": "src/main/java/com/example/shop/ReportQuery.java", "line": 48 }
                  ],
                  "match_mode": "relaxed", "unresolved_hops": 1 } },
    { "type": "ORACLE", "detail": { "oracle": "db_error", "canary_id": "elx-9d20" } }
  ],
  "confidence": 0.45,
  "confidence_reasons": [
    { "factor": "back_guided_unique_match", "delta": 0.55 },
    { "factor": "unresolved_hop", "delta": -0.1 }
  ]
}
```

The example values follow the defaults in the Config reference, which are `[proposed]`. The confidence is the start confidence minus one hop penalty, which is 0.45 with those defaults. That is at or above the confirm threshold, so the label is Confirmed. With two unresolved hops it would fall below the threshold, and the label would stay Runtime-only with the same evidence. With two candidate sinks the record would have `link_status: ambiguous`, `sink_id: null`, the candidates in `candidate_sinks`, and the label Runtime-only. The unresolved hop has `file: null`, because the receiver type did not resolve.

### Conflict case

The sink `OrderService.find` was marked `tested_negative`: every candidate param was probed and no oracle fired. A sweep probe then fired on `id`. The probe was replayed 3 times and fired in 2.

```json
{
  "label": "Runtime-only",
  "route": "/api/orders/{id}",
  "method": "GET",
  "param": "id",
  "cwe": 89,
  "sink_id": null,
  "candidate_sinks": [
    { "file": "src/main/java/com/example/shop/OrderService.java",
      "enclosing_method": "OrderService.find",
      "start_line": 88,
      "start_col": 31 }
  ],
  "status": null,
  "suppressed": false,
  "conflict": true,
  "link_status": "ambiguous",
  "link_origin": "sweep",
  "evidence": [
    { "type": "ORACLE",
      "detail": { "oracle": "db_error", "canary_id": "elx-31ab",
                  "replays": 3, "fired": 2, "oracle_flaky": false } }
  ],
  "confidence": "[TODO: float below the confirm threshold]",
  "confidence_reasons": [
    { "factor": "directed_probes_negative_positive_hit_on_replay", "delta": "[TODO: from config]" },
    { "factor": "oracle_fired_2_of_3_replays", "delta": "[TODO: from config]" }
  ]
}
```

This is the usual outcome. The confidence falls below `backguided.min_confidence_to_confirm`, so the label is Runtime-only, `conflict` stays true, `link_status` stays `ambiguous`, `sink_id` is null, and the sink is a hint in `candidate_sinks`. No Confirmed link is exported. The oracle hit is real, so it is not suppressed. The hit and the sink leave the suppressed file and enter the primary report.

At or above the threshold, the label would be Confirmed and `sink_id` would be set.

If the hit had fired in fewer than `replay.min_hits` replays, the sink would keep `status: tested_negative`. The `ORACLE` entry would carry `"oracle_flaky": true`. No link would be made. The hit would stay Runtime-only.
