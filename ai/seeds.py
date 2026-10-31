"""Advisory DTO seed proposal with repair (Should, after non-AI typed seeds work).

When the typed seed builder cannot fill a request body — an opaque DTO, a value
a validator rejects — this proposes benign field values. It is advisory and off
by default: the oracle still owns every verdict. A proposal that fails the
caller's validity check (for example, the baseline still does not reach the code)
is re-prompted up to `max_repairs` times, then the proposal is abandoned.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

SEED_TASK = "dto_seeds"
_SEED_SCHEMA = {
    "type": "object",
    "required": ["params"],
    "properties": {"params": {"type": "object"}},
}


def propose_seed(
    client,
    route: str,
    fields: Sequence[str],
    validate: Callable[[dict[str, str]], bool],
    *,
    max_repairs: int = 3,
) -> dict[str, str] | None:
    """Benign values for `fields`, repaired up to `max_repairs` times. Returns a
    param dict that passed `validate`, or None if the task is off or no proposal
    validated."""
    if client is None or not client.available(SEED_TASK):
        return None
    last_error = ""
    for _ in range(max(1, max_repairs)):
        proposed = client.complete(SEED_TASK, _prompt(route, fields, last_error), _SEED_SCHEMA)
        if proposed is None:
            return None
        params = {
            name: str(proposed["params"][name])
            for name in fields
            if name in proposed["params"]
        }
        if set(params) != set(fields):
            last_error = f"missing values for: {sorted(set(fields) - set(params))}"
            continue
        if validate(params):
            return params
        last_error = "the previous values did not produce a well-formed request"
    return None


def _prompt(route: str, fields: Sequence[str], last_error: str) -> str:
    repair = f" The previous attempt failed: {last_error}." if last_error else ""
    return (
        f"Propose benign, well-formed values for the request fields {list(fields)} "
        f"of route {route}, so the request is accepted by the application."
        f"{repair} Reply with JSON {{\"params\": {{<field>: <value>, ...}}}}. "
        "Use harmless values; this is a safe test request."
    )
