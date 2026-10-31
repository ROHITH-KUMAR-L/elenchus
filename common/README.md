# common/

**Owner:** joint (Person A and Person B). Changed only by joint agreement.

The shared contract. The only place both people touch.

| Path | Holds |
|---|---|
| `common/` | `record.py`: canonical `Finding` model and validation, `ScanTarget` (rejects non-localhost `base_url`), `RouteMap`, and contract logic `normalise_route()`, `dedupe_key()`, `route_key()`. Still to add: SARIF mapping, CWE/type ↔ VulnerableApp grader vocabulary map `[TODO: file names]`. |
| `common/fixtures/` | Hand-made sample records. Both sides test against them. Person A writes them right after the schema freeze. |

A schema change is a stop-the-world event. Agree it together, merge it, then both pull at once. See [CONTRIBUTING.md](../CONTRIBUTING.md).

Do not edit this dir without the other person's agreement.
