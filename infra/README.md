# infra/

`compose.yaml` runs the CLI container and the official `postgres:17-alpine` image. PostgreSQL uses the named volume `sastdast-pgdata` and private `sastdast-net` network. It publishes its port on `127.0.0.1` only (`POSTGRES_HOST_PORT`, default 5432), through a second bridge network `sastdast-hostport`, so a CLI running on the host can reach it (D-14). Never bind it to `0.0.0.0`. Keep the target app's Compose project separate.

The DAST-capable CLI runs on the host, so `localhost` reaches the target app. Point it at the database with `DATABASE_URL=postgresql://$POSTGRES_USER@127.0.0.1:5432/$POSTGRES_DB` and supply the password through `PGPASSWORD` or `~/.pgpass`, not in the URL.

Set credentials in the shell; do not commit them:

```sh
export POSTGRES_DB=elenchus
export POSTGRES_USER=elenchus
read -rsp "PostgreSQL password: " POSTGRES_PASSWORD
export POSTGRES_PASSWORD
printf '\n'
docker compose -f infra/compose.yaml up -d postgres
docker compose -f infra/compose.yaml run --rm cli correlate \
  --sast /workspace/sast.json --dast /workspace/dast.json
```

The CLI container mounts the repository read-only at `/workspace`. Input record files must be in the repository or another mounted location. The consumer only reads records; it does not scan source files or make HTTP requests.

Stop the database with `docker compose -f infra/compose.yaml down`. The volume persists. `docker compose -f infra/compose.yaml down -v` deletes the stored data; use that only for an intentional reset.

## ZAP and the practice target

Each has its own Compose file, pinned by digest and bound to loopback, so neither needs Postgres credentials:

```sh
docker compose -f infra/vulnerableapp.compose.yaml up -d
```

The CLI starts the pinned ZAP service automatically when its loopback API is
unavailable. On first scan without another configured key, it creates and
stores the API key in `~/.elenchus/zap.key` with owner-only permissions. An
already-running ZAP service is left untouched; if it rejects the stored key,
stop that service before rerunning the scan. Manual Compose startup still
requires `ZAP_API_KEY`.

`vulnerableapp.compose.yaml` runs VulnerableApp's base service only. Upstream's Compose file also starts Ollama, Mongo and an LLM service, and publishes their ports on all interfaces.

The VulnerableApp source for static stages goes in `.targets/`, which git and Docker ignore:

```sh
git clone https://github.com/SasanLabs/VulnerableApp.git .targets/VulnerableApp
```
