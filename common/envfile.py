"""A tiny .env loader, so configuration in a project .env file is picked up without
a shell export and without a new dependency.

It only fills variables that are not already set in the real environment, so an
explicit `export` or `docker run -e` always wins. Lines are `KEY=VALUE`; blank
lines and `#` comments are ignored; a leading `export ` and surrounding single or
double quotes on the value are stripped. A missing file is a no-op.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: Path | str = ".env") -> list[str]:
    """Populate os.environ from the file. Returns the names newly set."""
    file = Path(path)
    if not file.is_file():
        return []
    loaded: list[str] = []
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded
