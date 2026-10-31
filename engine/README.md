# engine/

**Owner:** Person B.

Everything that reads finding records. The engine never parses Java and never sends HTTP.

| Path | Holds |
|---|---|
| `engine/correlate/` | Tier A/B/C matching, dedupe/merge, labels, risk score. |
| `engine/store/` | Postgres persistence. |
| `engine/report/` | SARIF export, CLI report formatting. |

Built and tested against `common/fixtures/` before the real scanners exist.

Do not edit this dir if you don't own it.
