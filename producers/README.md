# producers/

**Owner:** Person A.

Everything that writes a finding record. A's job ends when a finding exists as a record.

| Path | Holds |
|---|---|
| `producers/sast/` | Semgrep runner. Spring MVC route-map parser. JAX-RS route-map adapter. |
| `producers/dast/` | ZAP runner. Deterministic oracles. |

All Java/framework-specific parsing and all HTTP attack logic live here and nowhere else. Entries: `route_map(target) -> RouteMap`, `run_sast(target, route_map) -> [Record]`, `run_dast(target, route_map) -> [Record]` (D-16). The route-map parser also emits one-hop call edges for `reached_via`.

Do not edit this dir if you don't own it.
