# tests/

**Owner:** split by subdir. Each owner tests their own component.

| Path | Owner | Tests |
|---|---|---|
| `tests/producers/` | Person A | SAST, route map, DAST, oracles |
| `tests/engine/` | Person B | Correlation, store, report |
| `tests/cli/` | Person B | The integration seam |

Subdir split is `[proposed]`. Both sides test against `common/fixtures/`. Never copy fixtures into a test dir.

Do not edit a subdir you don't own.
