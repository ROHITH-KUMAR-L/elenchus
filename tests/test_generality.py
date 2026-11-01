"""Generality guard: the tool must not be fitted to a practice target.

The sink catalogue, secrets rules and detection logic must not name a target
package, route, module or class. Target names may appear only in measurement-only
ground-truth fixtures, which never feed scanner logic (AGENTS.md, Generality).

The freeze test locks the catalogue and secrets-rule set to a recorded manifest,
so a change is a deliberate act and can be recorded as fitted in STATE.md.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Scanned for the app's Java package: it must never reach detection code or config.
TOOL_DIRS = ("producers", "probe", "engine", "common", "cli")
# The app's Java package root. A clean, target-specific canary.
APP_PACKAGE = "sasanlabs"
# Detection config must also be free of the app's own name.
DETECTION_YAML_BANNED = ("sasanlabs", "VulnerableApp")

# Measurement-only ground truth: allowed to name the target, never read by scanner.
ALLOWED = {
    ROOT / "common" / "fixtures" / "expected_pairs" / "vulnerableapp.yaml",
    ROOT / "common" / "fixtures" / "benchmarks" / "vulnerableapp-sast.json",
    ROOT / "common" / "fixtures" / "benchmarks" / "vulnerableapp-dast.json",
}


def _tool_sources() -> list[Path]:
    files: list[Path] = []
    for name in TOOL_DIRS:
        for path in (ROOT / name).rglob("*"):
            if path.suffix not in {".py", ".yaml", ".yml", ".json"}:
                continue
            if "/test" in path.as_posix() or path in ALLOWED:
                continue
            files.append(path)
    return files


def test_no_app_package_name_in_tool_code_or_config():
    offenders = [
        str(path.relative_to(ROOT))
        for path in _tool_sources()
        if APP_PACKAGE in path.read_text()
    ]
    assert offenders == [], f"test-app package '{APP_PACKAGE}' leaked into: {offenders}"


def test_detection_config_names_no_test_app():
    detection_yaml = [
        *(ROOT / "producers" / "sast" / "catalogue").glob("*.yaml"),
        ROOT / "producers" / "sast" / "secrets.yaml",
        *(ROOT / "producers" / "sast" / "rules").glob("*.yaml"),
    ]
    offenders = []
    for path in detection_yaml:
        if not path.exists():
            continue
        text = path.read_text()
        for token in DETECTION_YAML_BANNED:
            if token in text:
                offenders.append(f"{path.relative_to(ROOT)}: {token}")
    assert offenders == [], f"detection config names the test app: {offenders}"


def test_catalogue_matches_the_freeze_manifest():
    from producers.sast.secrets import load_rules
    from producers.sast.sink_finder import load_catalogue

    manifest = json.loads((ROOT / "producers" / "sast" / "catalogue" / "freeze.json").read_text())
    live_entries = sorted(e.entry_id for e in load_catalogue().entries)
    live_rules = sorted(k for k, v in load_rules().items() if isinstance(v, dict))
    assert live_entries == manifest["sink_entries"], (
        "sink catalogue changed since the freeze; update catalogue/freeze.json "
        "and record the change (fitted if based on the test app) in docs/STATE.md"
    )
    assert live_rules == manifest["secret_rules"], (
        "secrets rules changed since the freeze; update catalogue/freeze.json and docs/STATE.md"
    )
