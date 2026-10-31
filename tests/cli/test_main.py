from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from common.record import Finding, ScanTarget
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
    def test_scan_runs_route_map_then_both_producers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            order: list[str] = []
            routes = ("route-map",)
            sast = Finding.from_dict({**sast_record(), "run_id": "scan-run"})
            targets: list[ScanTarget] = []

            def build_routes(target: ScanTarget) -> tuple[str, ...]:
                order.append("route_map")
                targets.append(target)
                return routes

            def run_sast(target: ScanTarget, route_map: tuple[str, ...]) -> list[Finding]:
                order.append("run_sast")
                targets.append(target)
                self.assertEqual(route_map, routes)
                return [sast]

            def run_dast(target: ScanTarget, route_map: tuple[str, ...]) -> list[Finding]:
                order.append("run_dast")
                targets.append(target)
                self.assertEqual(route_map, routes)
                return []

            output = io.StringIO()
            with (
                patch("producers.sast.spring_routes.route_map", build_routes),
                patch("producers.sast.semgrep_runner.run_sast", run_sast),
                patch("producers.dast.zap_runner.run_dast", run_dast),
                contextlib.redirect_stdout(output),
            ):
                result = main(
                    [
                        "scan",
                        "--source-path",
                        temporary_directory,
                        "--base-url",
                        "http://localhost:9090/VulnerableApp",
                        "--run-id",
                        "scan-run",
                        "--no-store",
                    ]
                )

        self.assertEqual(result, 0)
        self.assertEqual(order, ["route_map", "run_sast", "run_dast"])
        self.assertEqual(
            [(item.source_path, item.base_url, item.run_id, item.framework) for item in targets],
            [
                (
                    temporary_directory,
                    "http://localhost:9090/VulnerableApp",
                    "scan-run",
                    "spring-mvc",
                )
            ] * 3,
        )
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
