# common/

**Owner:** joint (Person A and Person B). Changed only by joint agreement.

The shared contract. The only place both people touch.

| Path | Holds |
|---|---|
| `common/` | Canonical record model (`record.py` `[TODO: not written]`), `ScanTarget`, `RouteMap`, SARIF mapping, CWE/type ↔ VulnerableApp grader vocabulary map. Contract logic: `normalise_route(url, route_map)`, `dedupe_key(record)`. Other file names `[TODO]`. |
| `common/fixtures/` | Hand-made sample records. Both sides test against them. Person A writes them right after the schema freeze. |

A schema change is a stop-the-world event. Agree it together, merge it, then both pull at once. See [CONTRIBUTING.md](../CONTRIBUTING.md).

Do not edit this dir without the other person's agreement.
