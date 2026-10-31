from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cli.main import _apply_adequacy, _apply_conflict_resolution, _PipelineOutput, main
from common.pipeline import hypothesis_id
from common.record import Finding, SinkId
from engine.correlate.models import Issue
from probe.coordinator import ProbeAdequacy

ROUTE_PARAMS = {("/redirect", "GET"): ("next",)}


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


def adequate_row(
    *, params_status: str = "complete", after_drift: bool = False
) -> ProbeAdequacy:
    return ProbeAdequacy(
        job_id="j1",
        route="/redirect",
        method="GET",
        cwe=601,
        param="next",
        params_status=params_status,
        job_outcome="finished",
        expected_rule_ids=("10028",),
        observed_rule_ids=("10028",),
        baseline_status=200,
        response_statuses=(200,),
        passed_validation=True,
        outcome="adequate",
        after_drift=after_drift,
    )


class CliTests(unittest.TestCase):
    def test_adequacy_evidence_advances_complete_finding_to_tested_negative(self) -> None:
        finding = Finding.from_dict(
            {**sast_record(), "run_id": "adequacy-run", "status": "untested"}
        )
        adequacy = adequate_row()

        [updated] = _apply_adequacy([finding], [adequacy], ROUTE_PARAMS)

        self.assertEqual(updated.status, "tested_negative")
        self.assertEqual(updated.evidence[-1].type, "ADEQUACY")
        self.assertEqual(updated.evidence[-1].detail["observed_rule_ids"], ["10028"])

    def test_adequacy_does_not_clear_a_positive_oracle_hit(self) -> None:
        finding = Finding.from_dict(
            {**sast_record(), "run_id": "adequacy-run", "status": "untested"}
        )
        probe = Finding.from_dict(
            {
                "run_id": "adequacy-run",
                "source": "dast",
                "provenance": "zap",
                "cwe": 601,
                "type": "Open redirect",
                "route": "/redirect",
                "method": "GET",
                "param": "next",
                "evidence": [{"type": "ORACLE", "detail": {"oracle": "redirect_location"}}],
            }
        )
        adequacy = adequate_row()

        [updated, _] = _apply_adequacy([finding, probe], [adequacy], ROUTE_PARAMS)

        self.assertEqual(updated.status, "untested")

    def test_adequacy_keeps_incomplete_or_drifted_routes_untested(self) -> None:
        finding = Finding.from_dict(
            {**sast_record(), "run_id": "adequacy-run", "status": "untested"}
        )
        adequacy = adequate_row(params_status="partial", after_drift=True)

        [updated] = _apply_adequacy([finding], [adequacy], ROUTE_PARAMS)

        self.assertEqual(updated.status, "untested")

    def test_conflict_resolution_clears_the_persisted_static_status(self) -> None:
        original = Finding.from_dict(
            {
                **sast_record(),
                "run_id": "conflict-run",
                "status": "tested_negative",
                "suppressed": True,
            }
        )
        cleared = replace(original, status=None, suppressed=False, conflict=True)
        issue = Issue(
            issue_key="conflict-key",
            label="Confirmed",
            cwe=601,
            type="Open redirect",
            severity="high",
            risk_score=80.0,
            link_status="ambiguous",
            link_origin="sweep",
            conflict=True,
            sast_findings=(cleared,),
        )

        [updated] = _apply_conflict_resolution([original], [issue])

        self.assertIsNone(updated.status)
        self.assertFalse(updated.suppressed)
        self.assertTrue(updated.conflict)

    def test_scan_runs_the_pipeline_and_reports_its_findings(self) -> None:
        # The pipeline stages are exercised live in scripts/bs5_live_check.py;
        # here we patch the stage seam and check the CLI wires it to correlation.
        sast = Finding.from_dict({**sast_record(), "run_id": "scan-run"})
        captured: dict[str, object] = {}

        def fake_pipeline(args, run_id, config):
            captured["run_id"] = run_id
            captured["source_path"] = args.source_path
            captured["base_url"] = args.base_url
            return _PipelineOutput([sast])

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
            hid = hypothesis_id(
                "directed",
                "/redirect",
                "GET",
                601,
                SinkId.from_value(sast["sink_id"]),
                tuple(sast["candidate_params"]),
            )
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
                "hypothesis_id": hid,
                "evidence": [
                    {
                        "type": "ORACLE",
                        "detail": {
                            "oracle": "redirect_location",
                            "job_pass": "directed",
                            "hypothesis_ids": [hid],
                        },
                    }
                ],
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

    def test_suppressed_findings_are_written_separately_and_excluded_from_primary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = directory / "sast.json"
            output_dir = directory / "run-output"
            record = sast_record()
            record["arg_shape"] = "constant"
            record["status"] = "safe_pattern"
            input_path.write_text(json.dumps([record]), encoding="utf-8")
            output = io.StringIO()

            with (
                patch("cli.main._run_output_directory", return_value=output_dir),
                contextlib.redirect_stdout(output),
            ):
                result = main(
                    [
                        "correlate",
                        "--sast",
                        str(input_path),
                        "--no-store",
                        "--output-format",
                        "json",
                        "--run-id",
                        "suppression-test",
                    ]
                )

            primary = json.loads(output.getvalue())
            suppressed = json.loads((output_dir / "suppressed.json").read_text())
            coverage = json.loads((output_dir / "coverage.json").read_text())
            self.assertEqual(result, 0)
            self.assertEqual(primary["issues"], [])
            self.assertEqual(suppressed["issues"][0]["status"], "safe_pattern")
            self.assertTrue(suppressed["issues"][0]["suppressed"])
            self.assertEqual(coverage["recall_by_cwe"], {})


if __name__ == "__main__":
    unittest.main()
