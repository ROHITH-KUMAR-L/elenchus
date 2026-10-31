# producers/

**Owner:** Person A.

Everything that writes a finding record. A's job ends when a finding exists as a record.

| Path | Holds |
|---|---|
| `producers/sast/` | Semgrep taint/pattern rules and runner. Spring MVC route-map parser. |
| `producers/dast/` | Localhost-scoped ZAP API runner and deterministic response oracles. |

All Java/framework-specific parsing and all HTTP attack logic live here and nowhere else. Entries: `route_map(target) -> RouteMap`, `run_sast(target, route_map) -> [Record]`, `run_dast(target, route_map) -> [Record]` (D-16). The route-map parser emits bounded call edges for `reached_via`. `run_dast` only accepts localhost targets, scopes scans to the target origin and base path, and retains alerts only when deterministic response oracles confirm them.

The current tests exercise the runners with synthetic Java and a local fake ZAP API. No real ZAP daemon or VulnerableApp DAST scan has been run in this checkout. See the [architecture](../docs/architecture.md) for oracle limits and host placement.

Do not edit this dir if you don't own it.
