# Contributing

Work is organised by build stage, not by person. Build stages: [docs/implementation-plan.md](docs/implementation-plan.md#build-stages). Repo map: [docs/repo-structure.md](docs/repo-structure.md).

## Build stages

- [ ] Work on the current build stage. Do not start the next one until this one's exit test has run.
- [ ] Record the exit test output in `docs/STATE.md`.
- [ ] Keep the module boundary: static code and probe or engine code meet only through `common/` and `cli/`.
- [ ] Tests live under `tests/<component>/`.

## Schema is a contract change

- [ ] Freeze the record schema in `common/` in `BS1`, before anyone codes against it.
- [ ] Update `docs/finding-schema.md` first, and flag the change as a contract change.
- [ ] After a schema change merges, everyone pulls immediately.
- [ ] A mid-build schema change is stop-the-world. It is never a casual edit.

## Fixtures first

- [ ] Write the fixtures each build stage lists in `docs/implementation-plan.md`.
- [ ] Check each fixture against the correlation cases before the freeze.
- [ ] Test consumers against fixtures before the live stages that feed them exist.

## Branches

- [ ] One short-lived branch per task: `feat/<topic>`, e.g. `feat/bs2-code-index`.
- [ ] Pull `main` before each session.
- [ ] Rebase onto `main` rather than drift.

## PR cadence

- [ ] Small PRs, merged to `main` the same day.
- [ ] Small frequent merges over one big end-of-night merge.

## Docs

- [ ] `AGENTS.md`, `architecture.md`, `finding-schema.md`, `implementation-plan.md` and `STATE.md` are kept current while coding.
- [ ] `README.md` and `AGENTS.md` changes go in their own small PR, never alongside code.

## .gitignore policy

- [ ] Generated and volatile files never enter git: scan outputs, benchmark results (`benchmarks/*-results.json`), per-run SARIF, `__pycache__`, `.env`, virtualenvs, IDE folders.
- [ ] New generated file type? Add it to `.gitignore` in the same PR that creates it.

## Dependency files

- [ ] Dependency files are append-only.
- [ ] Resolve any conflict in them immediately after merge.
