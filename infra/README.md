# infra/

**Owner:** joint. Rare edits, coordinated like `common/`.

Intended home for our own stack's Docker definitions: the Postgres service, our Docker network and our named volume. Proposed names: `sastdast-postgres`, `sastdast-net`, `sastdast-pgdata`. See [docs/architecture.md](../docs/architecture.md).

The target app's Docker Compose is not kept here. The target runs from its own files on its own network.

Nothing is defined here yet. No compose file exists.

Do not edit this dir without the other person's agreement.
