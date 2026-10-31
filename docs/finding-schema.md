# Internal finding record (DRAFT contract)

Status: **DRAFT**. Every field is proposed. Ratify in hour one, then freeze.

Every component reads and writes this record. It is framework-agnostic: no Spring or JAX-RS field names.

Contract-freeze decisions recorded on branch `feat/contract-freeze`. See [decisions.md](decisions.md) D-07, D-15, D-16, D-17.

Change from the earlier draft: this record is the internal working format only. SARIF 2.1.0 is the interchange format at the edges: Semgrep SARIF in, correlated SARIF out (B-6). See [SARIF mapping](#sarif-mapping-ingestexport-lossy) and [decisions.md](decisions.md) D-13. The record is the source of truth. SARIF is for interop.

## Canonical definition

Code in `common/` is canonical. This doc is the human-readable description. When they disagree, the code wins.

Authoritative definition: [`common/record.py`](../common/record.py) (frozen dataclasses with validation in `Finding.from_dict`). It also defines `ScanTarget`, `RouteMap`, `normalise_route()`, `dedupe_key()` and `route_key()`.

`normalise_route(url, route_map, base_path="")` takes an optional `base_path` (from `ScanTarget.base_path`). It strips a servlet context path such as `/VulnerableApp` before matching, because route templates leave it out.

## Fields

| Field | Type | Meaning | Filled by |
|---|---|---|---|
| `run_id` | string | Scan run that produced the finding. Used for cross-run merge. | All |
| `source` | `"sast"` \| `"dast"` | Which scanner produced it. | All |
| `cwe` | integer | CWE number. Correlation join key. | SAST rule metadata; ZAP alert |
| `type` | string | Vulnerability type name from the grader vocabulary (see below). | Mapping table |
| `route` | string \| null | Normalised URL template, e.g. `/api/orders/{id}`. Always the output of `normalise_route()`. | DAST; route map for SAST |
| `method` | string \| null | HTTP method. Separates two bugs on the same route and CWE. | DAST; route map for SAST |
| `file` | string \| null | Source file, repo-relative. Sink file for SAST. | SAST; route map for DAST |
| `line` | integer \| null | Line of the finding (sink line for SAST). | SAST; route map for DAST |
| `param` | string \| null | Request parameter involved. Main wrong-link guard. | DAST; route map / taint source for SAST |
| `payload` | string \| null | Payload that triggered the finding. | DAST |
| `handler_file` | string \| null | File of the handler that contains the finding. Differs from `file` when the sink is in a service class. | SAST, when resolvable |
| `handler_line_start` | integer \| null | Handler span start. | SAST, when resolvable |
| `handler_line_end` | integer \| null | Handler span end. | SAST, when resolvable |
| `reached_via` | array \| null | Handlers that call the method holding the sink (one-hop call edges). Each entry: `route`, `method`, `handler_file`, `handler_line_start`, `handler_line_end`. Tier B matches on this. `[proposed: list, since one service method can be called from several handlers]` | SAST, from the route-map parser's call edges |
| `evidence` | object | Proof. DAST: oracle name, request, response excerpt. SAST: code snippet. Raw scanner severity also goes here. | All |
| `taint_trace` | array \| null | Source-to-sink path from Semgrep, within one function. Each step: `file`, `line`, `role` (`source` / `step` / `sink`). | SAST |
| `severity` | string \| null | The scanner's own severity claim. Shown in the report (FR-1). | Producer, when the scanner gives one |
| `wasc_id` | integer \| null | Passthrough for the VulnerableApp grader. Not used inside the engine. | ZAP alert |
| `label` | `"Confirmed"` \| `"Code-only"` \| `"Runtime-only"` | FR-7 label. Set by correlation, not by scanners. | Correlation engine |
| `confidence` | `"A"` \| `"B"` \| `"C"` \| null | Correlation tier that produced the link. Null if unlinked. | Correlation engine |
| `risk_score` | number \| null | Our ranking number. f(severity, exploit ease, confidence). Drives FR-9 ordering. Formula `[TODO: confirm at kickoff]`. | Correlation engine |

`severity` and `risk_score` are two fields. Do not collapse them. `severity` is the scanner's claim. `risk_score` is our ranking.

Handler fields are optional. A code-only secret has no handler.

## Other contract shapes

These live in `common/` with the record. Same freeze rules.

### ScanTarget

Immutable input config. Built once by the CLI.

| Field | Meaning |
|---|---|
| `source_path` | Target source folder |
| `base_url` | Target app on `localhost` |
| `run_id` | This run |
| `framework` | Adapter to use, e.g. Spring MVC `[proposed]` |

### RouteMap

Derived output of `route_map(target)`. One entry per handler.

| Field | Meaning |
|---|---|
| `route` | Normalised URL template |
| `method` | HTTP method |
| `file` | Handler file |
| `func` | Handler method name |
| `line_start`, `line_end` | Handler span |
| `params` | Request params the handler reads |
| `calls` | Methods the handler calls (one-hop call edges). Feeds `reached_via`. |

### Producer entries

```
route_map(target) -> RouteMap            # Person A. CLI calls first.
run_sast(target, route_map) -> [Record]  # Person A
run_dast(target, route_map) -> [Record]  # Person A. Uses the map to seed ZAP.
```

The CLI builds the map once, passes it to both scanners, then passes the map and all records to the engine.

### Contract logic

| Function | Rule |
|---|---|
| `normalise_route(url, route_map) -> template` | Maps a concrete URL (`/orders/5`) to its template (`/orders/{id}`) using the route map. Every `route` value comes from this. |
| `dedupe_key(record)` | `(cwe, file, line)` when file and line are present. Else `(cwe, route, method, param)`. App-wide header findings: `(cwe, header_name)`, with `header_name` read from `evidence` `[proposed]`. |

Header counting: does the answer key count a missing header per URL or per app? `[TODO: confirm at kickoff]`. Collapse to one per header for now. Flip if the answer key counts per URL.

### Merge rule

When the engine links a pair, it searches stored issues by both the code key and the route key. It merges into any match, including a stored Runtime-only issue. It creates a new issue only when neither key matches. Engine code is Person B's. The rule is frozen here because both keys must stay stable.

## Vocabulary alignment

The VulnerableApp grader (`POST /VulnerableApp/scanner/benchmark`) matches on its own canonical CWE/type vocabulary, defined in its `benchmarks/README.md`. Our `type` and `cwe` values must map onto it, or matches will miss.

| Our class | CWE | Grader `type` string |
|---|---|---|
| SQL injection | 89 | `[TODO: copy from benchmarks/README.md]` |
| XSS | 79 | `[TODO]` |
| Command injection | 78 | `[TODO]` |
| Open redirect | 601 | `[TODO]` |
| Path traversal (stretch) | 22 | `[TODO]` |
| Crypto / JWT stand-in (code-only) | `[TODO]` | `[TODO]` |

Grader request bodies, as stated in VulnerableApp's docs (not yet exercised by us):

- DAST: `{ tool, scanType: "DAST", findings: [ {url, type, cwe, wascId} ] }`
- SAST: `{ tool, scanType: "SAST", findings: [ {filePath, line, cwe, type} ] }`

The grader takes its own JSON. It is a third boundary format, separate from our SARIF export. Do not send SARIF to the grader.

## SARIF mapping (ingest/export, lossy)

SARIF is mapped to and from the internal record only at the edges.

**Ingest.** Semgrep SARIF output becomes internal records. `ruleId` and rule metadata give `cwe` and `type`. `locations` give `file` and `line`. Whether Semgrep's SARIF carries the dataflow trace (for `taint_trace`) is unverified: `[TODO: confirm at kickoff]`

**Export (B-6).** Each correlated issue becomes one SARIF `result`. Fields with no SARIF home go in `result.properties`. The mapping is lossy.

| Internal field | SARIF export location | Loss |
|---|---|---|
| `file`, `line` | `locations[0].physicalLocation` | None |
| `taint_trace` | `properties.taint_trace` | Ignored by most viewers |
| `reached_via` | `properties.reached_via`; each handler also in `relatedLocations` | Viewers show only the related locations |
| `method`, `handler_*`, `wasc_id` | `properties` | Ignored by most viewers |
| `cwe` | `properties.cwe`; rule tags `[TODO: GitHub code-scanning tag format]` | None in file |
| `type` | `ruleId`, `message.text` | None in file |
| `severity` | `level` (`error` / `warning` / `note`) | Coarser scale |
| `route`, `param`, `payload`, `evidence` | `properties` | Ignored by most viewers |
| `label`, `confidence`, `risk_score`, `run_id`, `source` | `properties` | Ignored by most viewers |

Runtime-only issues have no `file`/`line`. How to export them in SARIF: `[TODO: open question]`

CI mode: exit non-zero when any issue is `Confirmed` with high severity. Severity threshold: `[TODO: confirm]`

Example: the Confirmed SQLi issue from the examples below, exported as a SARIF result. Illustrative only.

```json
{
  "ruleId": "[TODO: rule id]",
  "level": "error",
  "message": { "text": "SQL injection (CWE-89). Confirmed." },
  "locations": [
    { "physicalLocation": {
        "artifactLocation": { "uri": "src/main/java/com/example/shop/OrderService.java" },
        "region": { "startLine": 88 } } }
  ],
  "relatedLocations": [
    { "id": 1,
      "message": { "text": "Reached via handler" },
      "physicalLocation": {
        "artifactLocation": { "uri": "src/main/java/com/example/shop/OrderController.java" },
        "region": { "startLine": 40 } } }
  ],
  "properties": {
    "run_id": "example-run",
    "cwe": 89,
    "label": "Confirmed",
    "confidence": "B",
    "risk_score": null,
    "route": "/api/orders/{id}",
    "method": "GET",
    "param": "id",
    "payload": "1'",
    "evidence": { "oracle": "db_error", "response_excerpt": "..." },
    "reached_via": [
      { "route": "/api/orders/{id}", "method": "GET",
        "handler_file": "src/main/java/com/example/shop/OrderController.java",
        "handler_line_start": 40, "handler_line_end": 47 }
    ]
  }
}
```

## Examples

Illustrative only. File paths, names and port are placeholders.

SAST finding in a Spring service class. The sink is in the service. The controller that calls it is in `reached_via`. Semgrep OSS gives a trace inside the service method only.

```json
{
  "run_id": "example-run",
  "source": "sast",
  "cwe": 89,
  "type": "[TODO: grader type]",
  "route": "/api/orders/{id}",
  "method": "GET",
  "file": "src/main/java/com/example/shop/OrderService.java",
  "line": 88,
  "param": "id",
  "payload": null,
  "handler_file": null,
  "handler_line_start": null,
  "handler_line_end": null,
  "reached_via": [
    { "route": "/api/orders/{id}", "method": "GET",
      "handler_file": "src/main/java/com/example/shop/OrderController.java",
      "handler_line_start": 40, "handler_line_end": 47 }
  ],
  "evidence": { "snippet": "stmt.executeQuery(\"SELECT * FROM orders WHERE id = \" + id)" },
  "taint_trace": [
    { "file": "src/main/java/com/example/shop/OrderService.java", "line": 85, "role": "source" },
    { "file": "src/main/java/com/example/shop/OrderService.java", "line": 88, "role": "sink" }
  ],
  "severity": "[TODO: Semgrep rule severity]",
  "wasc_id": null,
  "label": null,
  "confidence": null,
  "risk_score": null
}
```

`handler_*` is null here because the sink is not inside a handler. It would be filled if the sink sat directly in the controller method.

DAST finding from ZAP, after our oracle check.

```json
{
  "run_id": "example-run",
  "source": "dast",
  "cwe": 89,
  "type": "[TODO: grader type]",
  "route": "/api/orders/{id}",
  "method": "GET",
  "file": null,
  "line": null,
  "param": "id",
  "payload": "1'",
  "handler_file": null,
  "handler_line_start": null,
  "handler_line_end": null,
  "reached_via": null,
  "evidence": {
    "oracle": "db_error",
    "request": "GET http://localhost:[TODO: port]/api/orders/1'",
    "response_excerpt": "...",
    "scanner_severity": "[TODO: ZAP risk]"
  },
  "taint_trace": null,
  "severity": null,
  "wasc_id": "[TODO: from ZAP alert]",
  "label": null,
  "confidence": null,
  "risk_score": null
}
```

After correlation, both merge into one issue with `label: "Confirmed"` and `confidence: "B"`. Tier B matches because the DAST route and method appear in the SAST record's `reached_via`, with the same CWE and param.
