# Internal finding record (DRAFT contract)

Status: **DRAFT**. Every field is proposed. Ratify in hour one, then freeze.

Every component reads and writes this record. It is framework-agnostic: no Spring or JAX-RS field names.

Change from the earlier draft: this record is the internal working format only. SARIF 2.1.0 is the interchange format at the edges: Semgrep SARIF in, correlated SARIF out (B-6). See [SARIF mapping](#sarif-mapping-ingestexport-lossy) and [decisions.md](decisions.md) D-13. The record is the source of truth. SARIF is for interop.

## Fields

| Field | Type | Meaning | Filled by |
|---|---|---|---|
| `run_id` | string | Scan run that produced the finding. Used for cross-run merge. | All |
| `source` | `"sast"` \| `"dast"` | Which scanner produced it. | All |
| `cwe` | integer | CWE number. Correlation join key. | SAST rule metadata; ZAP alert |
| `type` | string | Vulnerability type name from the grader vocabulary (see below). | Mapping table |
| `route` | string | Method + URL template, e.g. `GET /api/orders/{id}`. | DAST; route map for SAST |
| `file` | string | Source file, repo-relative. | SAST; route map for DAST |
| `line` | integer | Line of the finding (sink line for SAST). | SAST; route map for DAST |
| `param` | string \| null | Request parameter involved. Main wrong-link guard. | DAST; route map / taint source for SAST |
| `payload` | string \| null | Payload that triggered the finding. | DAST |
| `evidence` | object | Proof. DAST: oracle name, request, response excerpt. SAST: code snippet. | All |
| `taint_trace` | array \| null | Source-to-sink path from Semgrep. Each step: `file`, `line`, `role` (`source` / `step` / `sink`). Needed by Tier B. | SAST |
| `label` | `"Confirmed"` \| `"Code-only"` \| `"Runtime-only"` | FR-7 label. Set by correlation, not by scanners. | Correlation engine |
| `confidence` | `"A"` \| `"B"` \| `"C"` \| null | Correlation tier that produced the link. Null if unlinked. | Correlation engine |
| `risk_score` | number | f(severity, exploit ease, confidence). Formula `[TODO: confirm at kickoff]`. | Correlation engine |

### Proposed additions (needed by the PRD, missing from the draft list)

| Field | Type | Why | Filled by |
|---|---|---|---|
| `severity` | string | FR-1 and FR-8 require severity. | SAST rule metadata; ZAP risk |
| `method` | string | FR-2 requires HTTP method. Could live inside `route` instead. | DAST; route map |
| `wasc_id` | integer \| null | Grader DAST body has `wascId`. | ZAP alert |

Whether to add these as fields or fold them into `route` / `evidence`: `[TODO: ratify in hour one]`

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
| `taint_trace` | `properties.taint_trace`; source end also in `relatedLocations` | Viewers show only the related location |
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
      "message": { "text": "Taint source" },
      "physicalLocation": {
        "artifactLocation": { "uri": "src/main/java/com/example/shop/OrderController.java" },
        "region": { "startLine": 42 } } }
  ],
  "properties": {
    "run_id": "example-run",
    "cwe": 89,
    "label": "Confirmed",
    "confidence": "B",
    "risk_score": null,
    "route": "GET /api/orders/{id}",
    "param": "id",
    "payload": "1'",
    "evidence": { "oracle": "db_error", "response_excerpt": "..." },
    "taint_trace": [
      { "file": "src/main/java/com/example/shop/OrderController.java", "line": 42, "role": "source" },
      { "file": "src/main/java/com/example/shop/OrderService.java", "line": 88, "role": "sink" }
    ]
  }
}
```

## Examples

Illustrative only. File paths, names and port are placeholders.

SAST finding in a Spring service class. The sink is in the service, and the taint source is in the controller.

```json
{
  "run_id": "example-run",
  "source": "sast",
  "cwe": 89,
  "type": "[TODO: grader type]",
  "route": "GET /api/orders/{id}",
  "file": "src/main/java/com/example/shop/OrderService.java",
  "line": 88,
  "param": "id",
  "payload": null,
  "evidence": { "snippet": "stmt.executeQuery(\"SELECT * FROM orders WHERE id = \" + id)" },
  "taint_trace": [
    { "file": "src/main/java/com/example/shop/OrderController.java", "line": 42, "role": "source" },
    { "file": "src/main/java/com/example/shop/OrderService.java", "line": 88, "role": "sink" }
  ],
  "label": null,
  "confidence": null,
  "risk_score": null
}
```

DAST finding from ZAP, after our oracle check.

```json
{
  "run_id": "example-run",
  "source": "dast",
  "cwe": 89,
  "type": "[TODO: grader type]",
  "route": "GET /api/orders/{id}",
  "file": null,
  "line": null,
  "param": "id",
  "payload": "1'",
  "evidence": {
    "oracle": "db_error",
    "request": "GET http://localhost:[TODO: port]/api/orders/1'",
    "response_excerpt": "..."
  },
  "taint_trace": null,
  "label": null,
  "confidence": null,
  "risk_score": null
}
```

After correlation, both merge into one issue with `label: "Confirmed"` and `confidence: "B"`.
