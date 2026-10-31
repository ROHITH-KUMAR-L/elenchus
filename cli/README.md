# cli/

**Owner:** Person B.

The current CLI consumes JSON records at the producer boundary and passes them to the engine. Producer entry modules and the canonical `common/` types are not in this checkout, so this CLI does not yet invoke `route_map`, `run_sast`, or `run_dast`. It does not scan source code or send HTTP.

## Install and run

Install the package in a Python 3.14+ environment:

```sh
python -m pip install .
elenchus correlate --sast sast.json --dast dast.json --no-store
```

Each input can be a JSON array of records or an object containing a `findings` array. Repeat `--sast` or `--dast` to combine files. The CLI assigns one run ID to all input records. Add `--no-store` for offline output; PostgreSQL persistence is enabled by default and requires `DATABASE_URL` or standard `PG*` environment variables.

```sh
elenchus correlate --sast sast.json --dast dast.json --no-store --output-format json
elenchus correlate --sast sast.json --dast dast.json --no-store --sarif-output out/report.sarif
elenchus correlate --sast sast.json --no-store --sarif-output - > out/report.sarif
elenchus correlate --sast sast.json --dast dast.json --no-store --ci
```

CI mode exits with status 1 when a Confirmed issue is High or Critical severity. Invalid records and database failures are reported to stderr and return status 2.

The CLI uses `DATABASE_URL` or standard `PG*` environment variables for PostgreSQL. See [infra/compose.yaml](../infra/compose.yaml) and [infra/README.md](../infra/README.md) to run the containerized CLI and database.

Use `--sarif-output -` to stream SARIF to standard output. This works with the read-only workspace mount used by the CLI container.
