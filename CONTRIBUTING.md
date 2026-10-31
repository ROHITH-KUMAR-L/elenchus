# Contributing

Two-person team. Rules to avoid merge conflicts. Ownership map: [docs/repo-structure.md](docs/repo-structure.md).

## Ownership

- [ ] Nobody edits another person's directory without asking.
- [ ] `producers/` is Person A: stages 1, 2 and 3, the back-guided search, the flow engine.
- [ ] The HTTP probe code is Person B: stages 0 and 4. Until `probe/` exists (proposed, not created), `producers/dast/` is Person B's.
- [ ] `engine/` and `cli/` are Person B.
- [ ] `common/` and `infra/` are joint.
- [ ] Tests live under `tests/<component>/`, owned by the component owner.

## Schema is a joint call

- [ ] Freeze the record schema in `common/` before anyone codes against it.
- [ ] Any change to it is decided together.
- [ ] After a schema change merges, both pull immediately.
- [ ] A mid-build schema change is stop-the-world. It is never a casual edit.

## Fixtures first

- [ ] Once the schema is frozen, Person A writes the fixtures listed in `docs/implementation-plan.md`.
- [ ] Person B reviews each fixture against the correlation cases before the freeze.
- [ ] Person B builds and tests stages 4 to 7 against the fixtures before Person A's stages exist.

## Branches

- [ ] One short-lived branch per task: `feat/<topic>`, e.g. `feat/sast-routemap`, `feat/correlation-tiers`.
- [ ] Pull `main` before each session.
- [ ] Pull `main` after the other person merges.
- [ ] Rebase onto `main` rather than drift.

## PR cadence

- [ ] Small PRs, merged to `main` the same day.
- [ ] Small frequent merges over one big end-of-night merge.

## Docs

- [ ] Person A owns `architecture.md` and `finding-schema.md` (A drafts, B reviews).
- [ ] Person B owns `implementation-plan.md` and `decisions.md`.
- [ ] `README.md` and `AGENTS.md`: whoever is free, in their own small PR, never alongside code.
- [ ] Never two people in one doc file.

## .gitignore policy

- [ ] Generated and volatile files never enter git: scan outputs, benchmark results (`benchmarks/*-results.json`), per-run SARIF, `__pycache__`, `.env`, virtualenvs, IDE folders.
- [ ] New generated file type? Add it to `.gitignore` in the same PR that creates it.

## Dependency files

- [ ] Dependency files (none exist yet) are append-only.
- [ ] Resolve any conflict in them immediately after merge.
