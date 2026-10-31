# infra/

**Owner:** joint.

`compose.yaml` runs the Person B CLI container and the official `postgres:17-alpine` image. PostgreSQL uses the named volume `sastdast-pgdata` and private `sastdast-net` network. It has no published host port. Keep the target app's Compose project separate.

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
