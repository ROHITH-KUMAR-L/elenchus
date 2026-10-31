# producers/

**Owner:** Person A.

Everything that writes a finding record. A's job ends when a finding exists as a record.

| Path | Holds |
|---|---|
| `producers/sast/` | Semgrep runner. Spring MVC route-map parser. JAX-RS route-map adapter. |
| `producers/dast/` | ZAP runner. Deterministic oracles. |

All Java/framework-specific parsing and all HTTP attack logic live here and nowhere else. Each producer exposes a `run()`-style entry that returns records. The CLI calls it. Exact signature: `[TODO: confirm at kickoff]`

Do not edit this dir if you don't own it.
