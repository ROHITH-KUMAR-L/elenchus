# engine/

**Owner:** Person B.

The engine only consumes finding records. It does not parse Java or send HTTP.

| Path | Holds |
|---|---|
| `engine/correlate/` | Record validation, deduplication, tiers A/B/C, labels, issue keys, and risk score. |
| `engine/store/` | PostgreSQL persistence for runs, raw findings, issue snapshots, and latest issues. |
| `engine/report/` | Plain-text issue report and SARIF 2.1.0 export. |

## Consumer contract and correlation behavior

The consumer validates the finding shape described in `docs/finding-schema.md`, including `method`, handler metadata, and `reached_via`. It does not change `common/` or define a producer schema.

Tier A matches a SAST sink inside its recorded handler span. Tier B matches the DAST route and method against a SAST `reached_via` edge. Tier C matches normalized route and method. Every tier also requires equal CWE and parameter. Route strings are compared exactly because the record contract requires them to be normalized before reaching the engine. If the best match is ambiguous, the engine leaves the findings unlinked.

Deduplication follows D-17: `(cwe, file, line)` when both location fields are present; otherwise `(cwe, route, method, param)`. App-wide header records use `(cwe, header_name)` from evidence. The issue store keeps code and route aliases so a later confirmed issue can merge with an earlier Code-only or Runtime-only issue. The provisional risk score is severity points (`critical 90`, `high 75`, `medium 50`, `low 25`, `info 10`, unknown `0`) plus a confidence bonus (`A 10`, `B 7`, `C 3`), capped at 100. Confirmed issues sort first. Confirm the formula before treating scores as benchmark results.

## Persistence

`PostgresStore` creates its tables transactionally on first use. PostgreSQL connection settings use `DATABASE_URL` or standard libpq environment variables (`PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`). A run is atomic and duplicate `run_id` values are rejected.

## Validation

Run the consumer tests from the repository root:

```sh
python -m unittest discover -s tests -t . -v
```
