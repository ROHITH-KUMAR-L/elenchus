from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cli.main import main
from common.record import Finding


def sast_record() -> dict[str, object]:
    return {
        "run_id": "producer-run",
        "source": "sast",
        "provenance": "own",
        "cwe": 601,
        "type": "Open redirect",
        "route": "/redirect",
        "method": "GET",
        "file": "src/RedirectController.java",
        "line": 44,
        "sink_id": {
            "file": "src/RedirectController.java",
            "enclosing_method": "RedirectController.go",
            "start_line": 44,
            "start_col": 10,
        },
        "arg_shape": "dynamic",
        "candidate_params": ["next"],
        "entry_paths": [
            {
                "route": "/redirect",
                "method": "GET",
                "hops": 0,
                "call_chain": [
                    {"method": "RedirectController.go", "file": "src/RedirectController.java", "line": 40}
                ],
            }
        ],
        "evidence": [
            {"type": "PATH", "detail": {"snippet": "redirect(request.getParameter(\"next\"))"}}
        ],
        "severity": "high",
    }


class CliTests(unittest.TestCase):
    def test_scan_runs_the_pipeline_and_reports_its_findings(self) -> None:
        # The pipeline stages are exercised live in scripts/bs5_live_check.py;
        # here we patch the stage seam and check the CLI wires it to correlation.
        sast = Finding.from_dict({**sast_record(), "run_id": "scan-run"})
        captured: dict[str, object] = {}

        def fake_pipeline(args, run_id, config):
            captured["run_id"] = run_id
            captured["source_path"] = args.source_path
            captured["base_url"] = args.base_url
            return [sast]

        output = io.StringIO()
        with (
            patch("cli.main._run_pipeline", fake_pipeline),
            contextlib.redirect_stdout(output),
        ):
            result = main(
                [
                    "scan",
                    "--source-path",
                    "src",
                    "--base-url",
                    "http://localhost:9090/VulnerableApp",
                    "--run-id",
                    "scan-run",
                    "--no-store",
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(captured["run_id"], "scan-run")
        self.assertEqual(captured["base_url"], "http://localhost:9090/VulnerableApp")
        self.assertIn("Code-only", output.getvalue())

    def test_scan_rejects_non_local_target_before_running_producers(self) -> None:
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            result = main(
                [
                    "scan",
                    "--source-path",
                    ".",
                    "--base-url",
                    "http://example.com",
                    "--no-store",
                ]
            )

        self.assertEqual(result, 2)
        self.assertIn("localhost", errors.getvalue())

    def test_correlate_reads_records_writes_json_and_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = directory / "sast.json"
            sarif_path = directory / "report.sarif"
            input_path.write_text(json.dumps([sast_record()]), encoding="utf-8")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(
                    [
                        "correlate",
                        "--sast",
                        str(input_path),
                        "--no-store",
                        "--output-format",
                        "json",
                        "--sarif-output",
                        str(sarif_path),
                        "--run-id",
                        "stable-run",
                    ]
                )

            report = json.loads(output.getvalue())
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            self.assertEqual(result, 0)
            self.assertEqual(report["issues"][0]["sast_findings"][0]["run_id"], "stable-run")
            self.assertEqual(sarif["version"], "2.1.0")

    def test_ci_fails_for_confirmed_high_severity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            sast_path = directory / "sast.json"
            dast_path = directory / "dast.json"
            sast = sast_record()
            dast = {
                "run_id": "producer-run",
                "source": "dast",
                "provenance": "zap",
                "cwe": 601,
                "type": "Open redirect",
                "route": "/redirect",
                "method": "GET",
                "param": "next",
                "payload": "https://evil.example",
                "evidence": [{"type": "ORACLE", "detail": {"oracle": "redirect_location"}}],
            }
            sast_path.write_text(json.dumps([sast]), encoding="utf-8")
            dast_path.write_text(json.dumps([dast]), encoding="utf-8")

            result = main(
                [
                    "correlate",
                    "--sast",
                    str(sast_path),
                    "--dast",
                    str(dast_path),
                    "--no-store",
                    "--ci",
                ]
            )

            self.assertEqual(result, 1)

    def test_missing_inputs_returns_an_error(self) -> None:
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            result = main(["correlate", "--no-store"])

        self.assertEqual(result, 2)
        self.assertIn("provide at least one", errors.getvalue())

    def test_sarif_can_be_streamed_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "sast.json"
            input_path.write_text(json.dumps([sast_record()]), encoding="utf-8")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(
                    [
                        "correlate",
                        "--sast",
                        str(input_path),
                        "--no-store",
                        "--sarif-output",
                        "-",
                    ]
                )

        report = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(report["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
