"""Parse Java response stack traces into adapter-neutral project frames."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_STACK_FRAME = re.compile(
    r"^\s*at\s+([\w.$<>/]+)\(([^():]+\.java):(\d+)\)\s*$"
)


def parse_java_response_trace(
    body: str, source_root: str | Path
) -> list[dict[str, str | int | bool]]:
    root = Path(source_root).resolve()
    frames = []
    for line in body.splitlines():
        match = _STACK_FRAME.match(line)
        if match is None:
            continue
        method, source_file, raw_line = match.groups()
        class_name, _, _ = method.rpartition(".")
        package = class_name.rpartition(".")[0]
        relative = Path(*package.split("."), source_file) if package else Path(source_file)
        resolved = _resolve_project_file(str(root), str(relative))
        is_project = resolved is not None
        frames.append(
            {
                "method": method,
                "file": resolved if resolved is not None else source_file,
                "line": int(raw_line),
                "project": is_project,
            }
        )
    return frames


@lru_cache(maxsize=512)
def _resolve_project_file(root_text: str, relative_text: str) -> str | None:
    root = Path(root_text)
    relative = Path(relative_text)
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if candidate.is_file():
        return candidate.relative_to(root).as_posix()

    suffix = relative.parts
    matches = [
        path
        for path in root.rglob(relative.name)
        if path.is_file() and path.relative_to(root).parts[-len(suffix) :] == suffix
    ]
    if len(matches) != 1:
        return None
    return matches[0].relative_to(root).as_posix()
