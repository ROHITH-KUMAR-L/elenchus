from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from cli.main import main


def sast_record() -> dict[str, object]:
    return {
        "run_id": "producer-run",
        "source": "sast",
        "cwe": 601,
        "type": "Open redirect",
        "route": "/redirect",
        "method": "GET",
        "file": "src/RedirectController.java",
        "line": 44,
        "param": "next",
        "payload": None,
        "handler_file": "src/RedirectController.java",
        "handler_line_start": 40,
        "handler_line_end": 50,
        "reached_via": None,
        "evidence": {"snippet": "redirect(request.getParameter(\"next\"))"},
        "taint_trace": None,
        "label": None,
        "confidence": None,
        "risk_score": None,
        "severity": "high",
        "wasc_id": None,
    }


class CliTests(unittest.TestCase):
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
            self.assertEqual(report["issues"][0]["finding"]["run_id"], "stable-run")
            self.assertEqual(sarif["version"], "2.1.0")

    def test_ci_fails_for_confirmed_high_severity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            sast_path = directory / "sast.json"
            dast_path = directory / "dast.json"
            sast = sast_record()
            dast = {
                **sast,
                "source": "dast",
                "file": None,
                "line": None,
                "handler_file": None,
                "handler_line_start": None,
                "handler_line_end": None,
                "payload": "https://evil.example",
                "evidence": {"oracle": "redirect_location"},
                "taint_trace": None,
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
