from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from common.record import CallEdge, RouteEntry, RouteMap, RouteParam, ScanTarget
from producers.sast import semgrep_runner


def target(source_path: Path) -> ScanTarget:
    return ScanTarget(str(source_path), "http://localhost:9090/VulnerableApp", "run-1", "spring-mvc")


def route_map(
    *,
    file: str = "src/OrderController.java",
    start: int = 10,
    end: int = 30,
    calls: tuple[CallEdge, ...] = (),
) -> RouteMap:
    return (
        RouteEntry(
            route="/orders/{id}",
            method="GET",
            file=file,
            func="OrderController.get",
            line_start=start,
            line_end=end,
            params=(RouteParam("id", "path"),),
            calls=calls,
        ),
    )


def sarif_result(
    *,
    file: str = "src/OrderController.java",
    line: int = 15,
    cwe: int = 89,
    rule_id: str = "java-injection.sql-injection",
    severity: str = "error",
    snippet: str = 'query("select " + id)',
) -> dict[str, Any]:
    return {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": rule_id,
                                "properties": {"tags": [str(cwe)]},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": severity,
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": file},
                                    "region": {
                                        "startLine": line,
                                        "snippet": {"text": snippet},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }


def test_run_semgrep_uses_target_root_and_raises_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(semgrep_runner.shutil, "which", lambda _: "/usr/bin/semgrep")
    completed = subprocess.CompletedProcess(
        args=["semgrep"],
        returncode=0,
        stdout=json.dumps({"runs": []}),
        stderr="",
    )
    run_calls: list[dict[str, Any]] = []

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        run_calls.append({"args": args, "kwargs": kwargs})
        return completed

    monkeypatch.setattr(semgrep_runner.subprocess, "run", fake_run)
    rules = tmp_path / "rules.yaml"

    assert semgrep_runner._run_semgrep(str(tmp_path), rules) == {"runs": []}
    assert run_calls[0]["kwargs"]["cwd"] == str(tmp_path)
    assert "--sarif" in run_calls[0]["args"][0]
    assert str(rules) in run_calls[0]["args"][0]

    failed = subprocess.CompletedProcess(
        args=["semgrep"], returncode=2, stdout="", stderr="configuration error"
    )

    def return_failure(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert args or kwargs
        return failed

    monkeypatch.setattr(semgrep_runner.subprocess, "run", return_failure)
    with pytest.raises(RuntimeError, match="configuration error"):
        semgrep_runner._run_semgrep(str(tmp_path), rules)


def test_run_sast_maps_findings_to_handler_entry_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sarif = sarif_result()

    def fake_run(source: str, rules: Path) -> dict[str, Any]:
        assert source == str(tmp_path)
        return sarif if rules == semgrep_runner.TAINT_RULES else {"runs": []}

    monkeypatch.setattr(semgrep_runner, "_run_semgrep", fake_run)

    [finding] = semgrep_runner.run_sast(target(tmp_path), route_map())

    assert finding.source == "sast"
    assert finding.cwe == 89
    assert finding.type == "SQL Injection"
    assert finding.route == "/orders/{id}"
    assert finding.method == "GET"
    assert finding.file == "src/OrderController.java"
    assert finding.provenance == "semgrep"
    assert finding.param is None
    assert finding.candidate_params == ("id",)
    assert finding.severity == "high"
    assert finding.taint_trace is None
    assert finding.entry_paths is not None
    [path] = finding.entry_paths
    assert (path.route, path.method, path.hops) == ("/orders/{id}", "GET", 0)
    assert path.call_chain[0].file == "src/OrderController.java"
    assert path.call_chain[0].line == 10
    assert finding.detail("scanner") == "semgrep"


def test_run_sast_attaches_service_sink_to_calling_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service_edge = CallEdge(
        type_name="OrderService",
        method="find",
        file="src/OrderService.java",
        line_start=50,
        line_end=55,
    )
    sarif = sarif_result(file="src/OrderService.java", line=52)

    def fake_run(source: str, rules: Path) -> dict[str, Any]:
        assert source == str(tmp_path)
        return sarif if rules == semgrep_runner.TAINT_RULES else {"runs": []}

    monkeypatch.setattr(semgrep_runner, "_run_semgrep", fake_run)

    [finding] = semgrep_runner.run_sast(
        target(tmp_path), route_map(calls=(service_edge,))
    )

    assert finding.file == "src/OrderService.java"
    assert finding.route == "/orders/{id}"  # Exactly one entry path reaches it.
    assert finding.param is None
    assert finding.candidate_params == ("id",)
    assert finding.entry_paths is not None
    [path] = finding.entry_paths
    assert path.hops == 1
    assert [hop.method for hop in path.call_chain] == ["OrderController.get", "OrderService.find"]


def test_unreachable_taint_findings_are_dropped_but_code_only_findings_remain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    taint_result = sarif_result(file="src/Unreachable.java")
    pattern_result = sarif_result(
        file="src/Secret.java",
        cwe=798,
        rule_id="java-pattern.hardcoded-secret",
        snippet='String password = "hardcoded-value";',
    )

    def fake_run(source: str, rules: Path) -> dict[str, Any]:
        assert source == str(tmp_path)
        return taint_result if rules == semgrep_runner.TAINT_RULES else pattern_result

    monkeypatch.setattr(semgrep_runner, "_run_semgrep", fake_run)

    findings = semgrep_runner.run_sast(target(tmp_path), ())

    assert len(findings) == 1
    assert findings[0].cwe == 798
    assert findings[0].route is None
    assert findings[0].entry_paths is None


def test_weak_random_rule_matches_java_random_in_security_method(
    tmp_path: Path,
) -> None:
    semgrep = shutil.which("semgrep")
    if semgrep is None:
        pytest.skip("Semgrep is required for the rule integration test")
    source = tmp_path / "TokenFactory.java"
    source.write_text(
        """
        import java.util.Random;

        class TokenFactory {
            String generateSessionToken() {
                return Integer.toString(new Random().nextInt());
            }
        }
        """,
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            semgrep,
            "scan",
            "--config",
            str(semgrep_runner.PATTERN_RULES),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    matches = [
        item
        for item in result["results"]
        if item["check_id"].endswith(".weak-random")
    ]
    assert len(matches) == 1
    assert matches[0]["start"]["line"] == 6


def test_real_semgrep_taint_result_maps_to_contract_without_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if shutil.which("semgrep") is None:
        pytest.skip("Semgrep is required for the rule integration test")
    source_path = tmp_path / "target"
    java_file = source_path / "src" / "Orders.java"
    java_file.parent.mkdir(parents=True)
    java_file.write_text(
        """
        class Orders {
            void find(String id) {
                jdbc.query("select * from orders where id = " + id);
            }
        }
        """,
        encoding="utf-8",
    )
    target_record = target(source_path)
    routes = route_map(
        file="src/Orders.java",
        start=2,
        end=4,
    )

    original_run = semgrep_runner._run_semgrep
    taint_sarif: list[dict[str, Any]] = []

    def capture_sarif(source: str, rules: Path) -> dict[str, Any]:
        output = original_run(source, rules)
        if rules == semgrep_runner.TAINT_RULES:
            taint_sarif.append(output)
        return output

    monkeypatch.setattr(semgrep_runner, "_run_semgrep", capture_sarif)
    findings = semgrep_runner.run_sast(target_record, routes)
    sql_findings = [finding for finding in findings if finding.cwe == 89]

    assert len(taint_sarif) == 1
    raw_results = []
    for result, rule in semgrep_runner._sarif_results(taint_sarif[0]):
        assert isinstance(rule, dict)
        raw_results.append(result)
    assert raw_results
    assert all("codeFlows" not in result for result in raw_results)
    assert len(sql_findings) == 1
    finding = sql_findings[0]
    assert finding.file == "src/Orders.java"
    assert finding.route == "/orders/{id}"
    assert finding.param is None
    assert finding.candidate_params == ("id",)
    assert finding.taint_trace is None


def test_java_rule_sets_match_covered_vulnerability_families(
    tmp_path: Path,
) -> None:
    semgrep = shutil.which("semgrep")
    if semgrep is None:
        pytest.skip("Semgrep is required for the rule integration test")
    source = tmp_path / "RuleSamples.java"
    source.write_text(
        """
        import java.io.FileInputStream;
        import java.security.MessageDigest;
        import java.util.Random;
        import javax.crypto.Cipher;

        class RuleSamples {
            String query(String id) {
                return jdbc.query("select * from orders where id=" + id);
            }

            void command(String cmd) throws Exception {
                Runtime.getRuntime().exec(cmd);
            }

            String render(String value) {
                return "<p>" + value + "</p>";
            }

            void redirect(String target) {
                response.sendRedirect(target);
            }

            void readFile(String path) throws Exception {
                new FileInputStream(path);
            }

            void cryptography() throws Exception {
                MessageDigest.getInstance("MD5");
                Cipher.getInstance("DES");
                new BCryptPasswordEncoder(4);
            }

            String createSessionToken() {
                return Integer.toString(new Random().nextInt());
            }

            void credentials() {
                String apiKey = "hardcoded-secret-value";
            }
        }
        """,
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            semgrep,
            "scan",
            "--config",
            str(semgrep_runner.TAINT_RULES),
            "--config",
            str(semgrep_runner.PATTERN_RULES),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    rule_ids = {item["check_id"].rsplit(".", 1)[-1] for item in result["results"]}
    assert {
        "sql-injection",
        "command-injection",
        "xss",
        "open-redirect",
        "path-traversal",
        "weak-hash",
        "weak-cipher",
        "weak-password-hash-cost",
        "weak-random",
        "hardcoded-secret",
    } <= rule_ids
