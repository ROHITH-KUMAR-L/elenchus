# Repo structure and ownership

The authoritative ownership map. Check here when unsure who owns what. Rules for working within it: [CONTRIBUTING.md](../CONTRIBUTING.md).

Person A and Person B are role labels. Who is who: `[TODO: confirm at kickoff]`

## Tree

```
.
├── AGENTS.md            whoever is free, own PR
├── CONTRIBUTING.md      [TODO: owner]
├── README.md            whoever is free, own PR
├── .gitignore           [TODO: owner]
├── common/              JOINT, by agreement only
│   └── fixtures/        sample records (A writes, both use)
├── producers/           PERSON A
│   ├── sast/            Semgrep runner, Spring + JAX-RS route maps
│   └── dast/            ZAP runner, oracles
├── engine/              PERSON B
│   ├── correlate/       tiers A/B/C, dedupe/merge, labels, risk score
│   ├── store/           Postgres persistence
│   └── report/          SARIF export, CLI report
├── cli/                 PERSON B, the single integration seam
├── infra/               JOINT, rare edits
├── docs/                split by file
└── tests/
    ├── producers/       PERSON A
    ├── engine/          PERSON B
    └── cli/             PERSON B
```

## Owner per directory

| Directory | Owner | Holds |
|---|---|---|
| `common/` | Joint | Finding-record schema, SARIF mapping, CWE/type ↔ grader vocabulary map |
| `common/fixtures/` | Joint (A writes first set) | Hand-made sample records |
| `producers/sast/` | Person A | Semgrep runner, Spring MVC route-map parser, JAX-RS route-map adapter |
| `producers/dast/` | Person A | ZAP runner, deterministic oracles |
| `engine/correlate/` | Person B | Tier A/B/C matching, dedupe/merge, labels, risk score |
| `engine/store/` | Person B | Postgres persistence |
| `engine/report/` | Person B | SARIF export, CLI report formatting |
| `cli/` | Person B | Wires producers to engine |
| `infra/` | Joint | Our stack's Docker definitions (not written yet) |
| `docs/` | Per file | See [docs/README.md](README.md) |
| `tests/<component>/` | Component owner | Tests against `common/fixtures/` |

## The record-contract boundary

The cut follows the finding record.

- **Person A builds producers.** Everything that writes a record. A owns all Java/framework parsing and all HTTP attack logic. A's job ends when a finding exists as a record.
- **Person B builds consumers.** Everything that reads records. B never parses Java and never sends HTTP.
- They meet only through the contract in `common/`. Never through shared code. No producer module imports engine code, and no engine module imports producer code.

```
producers/ (A) --writes--> record contract (common/) --read by--> engine/ (B)
                                    ^
                                    |
                         cli/ (B) calls producers' run() entries,
                         passes records to engine
```

## Fixtures first

1. Freeze the schema in `common/` in hour one.
2. Person A writes 5–6 sample records into `common/fixtures/` right away:

| Fixture | Purpose |
|---|---|
| One Confirmed pair (SAST + DAST) | Basic link |
| Spring case: sink in a service class, outside the handler span | Target for Tier B |
| One Code-only | Unlinked SAST path |
| One Runtime-only | Unlinked DAST path |
| One decoy that must not link | Wrong-link guard |

3. Person B builds and tests the whole engine against these before A's real scanners exist.
4. Fixtures sit in `common/`, so changing them is a joint call.

## The cli/ integration seam

- Each producer exposes a `run()`-style entry that returns records. Signature: `[TODO: confirm at kickoff]`
- `cli/` calls those entries and passes the records to the engine.
- This is the only place the two halves connect. It sits on B's side, so there is no shared orchestration file.
- If A needs a producer entry to change shape, that is a contract change in `common/`, agreed jointly.
