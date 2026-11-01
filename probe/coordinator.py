"""Stage 4 coordinator: run one ZAP active-scan job per (route, method), attribute
each request, and confirm candidates by replay.

The design is from docs/architecture.md (Stage 4). BS4 builds the spine for
error-based SQL injection; the two-pass scheduler, the state guard and the other
classes arrive in BS6. ZAP generates the attacks; the project owns the verdict,
which comes from a deterministic oracle on a coordinator replay, never from an
alert. Lineage is recorded in the ProbeJob before the scan, so a confirmed hit
carries the job's hypotheses without any after-the-fact matching.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from common.config import Config
from common.pipeline import Hypothesis, ProbeJob, SeedRequest
from common.record import Finding, RouteEntry
from common.vocabulary import type_name
from probe.attribution import PROBE_HEADER, RULE_HEADER, attribute, request_values
from probe.headers import HeaderFinding, check_response
from probe.oracles import Response, oracle_for, sql_boolean, timing_slower
from probe.preflight import ContextPath
from probe.scheduler import run_two_pass
from probe.seeds import build_seed
from probe.session import login_configured, resolve_session

# ZAP input-vector bitmask: query string (1) and POST data (2). The URL-path
# vector stays off here; a path-param sink needs the scoped handling added in BS6.
_INJECTABLE_QUERY_AND_BODY = "3"
_POLL_SECONDS = 0.5
_BLOCKING_STATUSES = range(400, 600)
_ADEQUACY_REJECTIONS = {400, 401, 403, 404, 422}
# State-guard method risk: GET/HEAD/ANY are read-only; the rest change state and
# run last, so the safe reads are done before anything can drift the app.
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "ANY"}
_METHOD_RANK = {"GET": 0, "HEAD": 0, "OPTIONS": 0, "ANY": 0, "POST": 1, "PUT": 2, "PATCH": 2, "DELETE": 3}
# A destructive SQL verb in the seed pushes the job last within its risk rank.
_DESTRUCTIVE_SQL = re.compile(r"\b(DROP|DELETE|TRUNCATE|UPDATE|ALTER|INSERT)\b", re.IGNORECASE)
# Boolean-based blind SQL: (true-suffix, false-suffix) appended to the seed value.
# The true branch should answer like the baseline, the false branch differently.
_BOOLEAN_TEMPLATES = (
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1' -- ", "' AND '1'='2' -- "),
)
# Time-based blind SQL: a payload that makes the database sleep. The project times
# the replay and compares it against a benign baseline (timing_slower). Wired but
# gated on probe.timing_repeats: it needs a measured repeat count and a live
# baseline before it is trusted, so it stays off until that is recorded.
_TIMING_SLEEP_SECONDS = 5
_TIMING_THRESHOLD_SECONDS = _TIMING_SLEEP_SECONDS * 0.5
_TIMING_TEMPLATES = (
    "' AND SLEEP({s})-- ",
    " AND SLEEP({s})",
    "'; WAITFOR DELAY '0:0:{s}'-- ",
    "' AND (SELECT 1 FROM PG_SLEEP({s}))-- ",
)
# OS command injection: append a shell separator and a benign, read-only command
# (`id`) whose output the command_output oracle recognises. Project-controlled, so
# confirmation does not depend on which payload ZAP happened to send.
_COMMAND_TEMPLATES = (";id", " && id", " | id", "`id`", "$(id)", "& id")


def _command_payloads(value: str, canary: str) -> list[str]:
    return [value + separator for separator in _COMMAND_TEMPLATES]


def _xss_payloads(value: str, canary: str) -> list[str]:
    # A single canary tag with angle brackets: reflected verbatim means unescaped.
    return [f"<elx-{canary}>"]


def _redirect_payloads(value: str, canary: str) -> list[str]:
    # An external host the open_redirect oracle checks for in the Location header.
    return [f"http://elx-{canary}.example/"]


# Injection classes confirmed by project-controlled payloads (CWE -> payload maker).
# SQL (89) is confirmed by the error oracle on ZAP's scan plus the boolean/timing
# passes, so it is not here.
_CONFIRM_PAYLOADS = {78: _command_payloads, 79: _xss_payloads, 601: _redirect_payloads}


def _is_state_changing(method: str) -> bool:
    return method.upper() not in _SAFE_METHODS


def _risk_key(job: ProbeJob, index: int) -> tuple[int, int, int]:
    seed = job.seed_request
    destructive = 1 if _DESTRUCTIVE_SQL.search(f"{seed.url} {seed.body}") else 0
    return (_METHOD_RANK.get(job.method.upper(), 1), destructive, index)
_TYPE_REJECTION_STATUSES = {400, 422}
_TYPE_REJECTABLE = {
    "byte", "short", "int", "integer", "long", "float", "double",
    "boolean", "uuid", "byte[]", "short[]", "int[]", "long[]",
    "java.lang.byte", "java.lang.short", "java.lang.integer", "java.lang.long",
    "java.lang.float", "java.lang.double", "java.lang.boolean", "java.util.uuid",
}


class ZapApiLike(Protocol):
    base_url: str

    def set_option(self, component: str, option: str, type_name: str, value: str) -> None: ...
    def ensure_scan_policy(self, name: str, rule_ids: list[str], strength: str) -> None: ...
    def create_context(self, name: str, scope_regex: str) -> str: ...
    def remove_context(self, name: str) -> None: ...
    def replacer_rules(self) -> list[dict[str, Any]]: ...
    def add_replacer_request_header(self, description: str, header: str, value: str) -> None: ...
    def remove_replacer_rule(self, description: str) -> None: ...
    def prime_site_tree(self, url: str, method: str, body: str, content_type: str) -> None: ...
    def send_request(self, raw_request: str, follow_redirects: bool = ...) -> dict[str, Any]: ...
    def start_scan(self, url: str, method: str, post_data: str, context_id: str, policy: str) -> str: ...
    def stop_scan(self, scan_id: str) -> None: ...
    def active_scan_status(self, scan_id: str) -> int: ...
    def scan_message_ids(self, scan_id: str) -> list[str]: ...
    def message(self, message_id: str) -> dict[str, Any]: ...
    def hosts(self) -> list[str]: ...


@dataclass
class ProbeResult:
    findings: list[Finding]
    jobs: list[ProbeJob]
    attribution_rate: float
    header_propagation_rate: float
    adequacy: list[ProbeAdequacy] = field(default_factory=list)
    foreign_hosts: list[str] = field(default_factory=list)
    jobs_skipped: list[tuple[str, str]] = field(default_factory=list)  # (job_id, reason)
    stage_seconds: float = 0.0
    drift_detected: bool = False
    advisory_alerts: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ProbeAdequacy:
    job_id: str
    route: str
    method: str
    cwe: int
    param: str
    params_status: str
    job_outcome: str
    expected_rule_ids: tuple[str, ...]
    observed_rule_ids: tuple[str, ...]
    baseline_status: int | None
    response_statuses: tuple[int | None, ...]
    passed_validation: bool
    outcome: str
    sub_code: str | None = None
    after_drift: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "route": self.route,
            "method": self.method,
            "cwe": self.cwe,
            "param": self.param,
            "params_status": self.params_status,
            "job_outcome": self.job_outcome,
            "expected_rule_ids": list(self.expected_rule_ids),
            "observed_rule_ids": list(self.observed_rule_ids),
            "baseline_status": self.baseline_status,
            "response_statuses": list(self.response_statuses),
            "passed_validation": self.passed_validation,
            "outcome": self.outcome,
            "sub_code": self.sub_code,
            "after_drift": self.after_drift,
        }


def plan_directed_jobs(
    hypotheses: list[Hypothesis], index_routes: tuple[RouteEntry, ...], run_id: str
) -> list[ProbeJob]:
    """One ProbeJob per (route, method), covering the directed hypotheses there."""
    routes = {(r.route, r.method): r for r in index_routes}
    grouped: dict[tuple[str, str], list[Hypothesis]] = {}
    for hypothesis in hypotheses:
        if hypothesis.kind == "directed":
            grouped.setdefault((hypothesis.route, hypothesis.method), []).append(hypothesis)
    jobs = []
    for index, ((route, method), group) in enumerate(sorted(grouped.items())):
        entry = routes.get((route, method))
        if entry is None:
            continue
        jobs.append(
            ProbeJob(
                job_id=f"{run_id}-j{index}",
                route=route,
                method=method,
                job_pass="directed",
                hypothesis_ids=tuple(h.hypothesis_id for h in group),
                cwes=tuple(sorted({h.cwe for h in group})),
                seed_request=build_seed(entry, _route_base(entry, route)),
                canary=f"elx-{run_id}-j{index}",
            )
        )
    return jobs


def plan_sweep_jobs(
    hypotheses: list[Hypothesis], index_routes: tuple[RouteEntry, ...], run_id: str
) -> list[ProbeJob]:
    """One sweep ProbeJob per (route, method), covering the sweep hypotheses there.

    Sweep jobs run after directed jobs, in the time the two-pass scheduler leaves.
    Each carries every sweep CWE for its route, so one scan covers them together.
    """
    routes = {(r.route, r.method): r for r in index_routes}
    grouped: dict[tuple[str, str], list[Hypothesis]] = {}
    for hypothesis in hypotheses:
        if hypothesis.kind == "sweep":
            grouped.setdefault((hypothesis.route, hypothesis.method), []).append(hypothesis)
    jobs = []
    for index, ((route, method), group) in enumerate(sorted(grouped.items())):
        entry = routes.get((route, method))
        if entry is None:
            continue
        jobs.append(
            ProbeJob(
                job_id=f"{run_id}-s{index}",
                route=route,
                method=method,
                job_pass="sweep",
                hypothesis_ids=tuple(h.hypothesis_id for h in group),
                cwes=tuple(sorted({h.cwe for h in group})),
                seed_request=build_seed(entry, _route_base(entry, route)),
                canary=f"elx-{run_id}-s{index}",
            )
        )
    return jobs


def _auth_header(config: Config) -> tuple[str, str] | None:
    """The optional target auth header: a header name from config and a value read
    from the environment variable config names. Credentials never sit in config."""
    import os

    name = config["target.auth.header_name"]
    env = config["target.auth.value_env"]
    if not name or not env:
        return None
    value = os.environ.get(env)
    if not value:
        raise ValueError(f"target.auth.header_name is set but {env} is empty in the environment")
    return name, value


def _route_base(entry: RouteEntry, route: str) -> str:
    # build_seed needs base_url; plan_directed_jobs is given routes only, so the
    # coordinator rebuilds seeds against the real base_url. This placeholder keeps
    # ProbeJob self-describing for logs and tests.
    return "http://127.0.0.1"


@dataclass(frozen=True)
class _Candidate:
    param: str
    cwe: int
    payload: str
    rule_id: str
    message_id: str
    param_location: str | None = None
    param_path: str | None = None


class Coordinator:
    def __init__(
        self,
        api: ZapApiLike,
        config: Config,
        base_url: str,
        context: ContextPath,
        *,
        enum_types: frozenset[str] = frozenset(),
        trace_parser: Callable[[str], list[dict[str, Any]]] | None = None,
    ) -> None:
        self.api = api
        self.config = config
        self.base_url = base_url.rstrip("/")
        self.context = context
        self.rule_cwes = {rule: cwe for cwe, rules in config.rule_map().items() for rule in rules}
        self.rule_ids_by_cwe = config.rule_map()
        self._auth = _auth_header(config)
        self._login = login_configured(config)
        self._sleep = time.sleep
        self._now = time.monotonic
        self.enum_types = enum_types
        self.trace_parser = trace_parser

    def run(
        self,
        run_id: str,
        jobs: list[ProbeJob],
        routes: tuple[RouteEntry, ...],
        progress_callback: Callable[[str, ProbeJob, int, int], None] | None = None,
    ) -> ProbeResult:
        entries = {(r.route, r.method): r for r in routes}
        context_id = self.api.create_context(f"elenchus-{run_id}", self._scope_regex())
        findings: list[Finding] = []
        adequacy: list[ProbeAdequacy] = []
        totals = {"considered": 0, "attributed": 0, "with_header": 0, "messages": 0}
        # One finding per missing protection across the whole app (per_app dedupe).
        header_hits: dict[tuple[int, str], tuple[str, HeaderFinding]] = {}
        # State guard: run read-only jobs first, watch a sample of GET routes, and
        # stop state-changing jobs once the app drifts. It limits damage; it does
        # not prevent it.
        ordered = sorted(
            range(len(jobs)),
            key=lambda i: _risk_key(
                replace(jobs[i], seed_request=build_seed(entries[(jobs[i].route, jobs[i].method)], self.base_url)),
                i,
            ),
        )
        ordered = [jobs[i] for i in ordered]
        drift = {"detected": False}
        completed_jobs = 0
        start = self._now()
        try:
            # Session manager: mint the auth header from the login flow, if one is
            # configured, before anything carries it. It overrides the static header.
            if self._login:
                self._auth = resolve_session(self.api, self.config, self.base_url)
            self._set_auth_header()
            self.api.set_option("ascan", "InjectPluginIdInHeader", "Boolean", "true")
            self.api.set_option(
                "ascan", "ThreadPerHost", "Integer", str(self.config["zap.thread_per_host"])
            )
            self.api.set_option(
                "ascan", "TargetParamsInjectable", "Integer", _INJECTABLE_QUERY_AND_BODY
            )
            has_state_change = any(_is_state_changing(job.method) for job in ordered)
            baselines = self._drift_baselines(routes) if has_state_change else {}

            def run_one(job: ProbeJob) -> ProbeJob:
                entry = entries[(job.route, job.method)]
                seed = build_seed(entry, self.base_url)
                # After drift, run no further state-changing job; read-only jobs
                # still run. Everything run after drift is flagged, so a negative
                # on a drifted app is never read as tested_negative.
                if drift["detected"] and _is_state_changing(job.method):
                    return replace(job, seed_request=seed, outcome="skipped_drift", after_drift=True)
                # One job's ZAP failure (a stalled or rejected API call) must not
                # abort the run: record it as errored and move on, so the budget
                # and the other jobs still hold.
                try:
                    outcome, job_findings, headers, stats, job_adequacy = self._run_job(
                        run_id, replace(job, after_drift=drift["detected"]), entry, seed, context_id
                    )
                except RuntimeError:
                    return replace(job, seed_request=seed, outcome="errored", after_drift=drift["detected"])
                findings.extend(job_findings)
                adequacy.extend(job_adequacy)
                for key in totals:
                    totals[key] += stats[key]
                for header in headers:
                    header_hits.setdefault((header.cwe, header.header_name), (job.route, header))
                if _is_state_changing(job.method) and not drift["detected"] and self._drifted(baselines):
                    drift["detected"] = True
                return replace(job, seed_request=seed, outcome=outcome, after_drift=drift["detected"])

            def run_one_with_progress(job: ProbeJob) -> ProbeJob:
                nonlocal completed_jobs
                if progress_callback is not None:
                    progress_callback("started", job, completed_jobs, len(ordered))
                result = run_one(job)
                completed_jobs += 1
                if progress_callback is not None:
                    progress_callback("completed", result, completed_jobs, len(ordered))
                return result

            schedule = run_two_pass(
                ordered, self.config["probe.stage_budget_seconds.zap_jobs"], self._now, run_one_with_progress
            )
            executed = list(schedule.ran)
            executed.extend(replace(job, outcome="skipped_budget") for job, _ in schedule.skipped)
            known_jobs = {item.job_id for item in adequacy}
            for job in executed:
                if job.job_id not in known_jobs:
                    entry = entries[(job.route, job.method)]
                    for cwe in job.cwes:
                        adequacy.extend(
                            _empty_adequacy(
                                job,
                                entry,
                                cwe,
                                "untested",
                                self.rule_ids_by_cwe.get(cwe, ()),
                                job.outcome or "untested",
                                after_drift=job.after_drift,
                            )
                        )
            findings.extend(
                self._header_finding(run_id, route, header)
                for route, header in header_hits.values()
            )
            foreign = [host for host in self.api.hosts() if not _is_loopback(host)]
            advisory = self._collect_advisory_alerts()
        finally:
            self._clear_auth_header()
            self.api.remove_context(f"elenchus-{run_id}")
        considered, messages = totals["considered"], totals["messages"]
        return ProbeResult(
            findings=findings,
            jobs=executed,
            attribution_rate=(totals["attributed"] / considered) if considered else 1.0,
            header_propagation_rate=(totals["with_header"] / messages) if messages else 1.0,
            adequacy=adequacy,
            foreign_hosts=foreign,
            jobs_skipped=[(job.job_id, reason) for job, reason in schedule.skipped],
            stage_seconds=round(self._now() - start, 3),
            drift_detected=drift["detected"],
            advisory_alerts=advisory,
        )

    def _collect_advisory_alerts(self) -> list[dict[str, Any]]:
        """ZAP's passive alerts as advisory context. Best effort: the active scan
        and its oracle verdicts do not depend on it, so a failure here is ignored.
        Alerts from our own active scanners are dropped; the oracles judged those."""
        from probe.passive import ingest

        reader = getattr(self.api, "alerts", None)
        if reader is None:
            return []
        active = {rule for rules in self.rule_ids_by_cwe.values() for rule in rules}
        try:
            raw = reader(self.base_url)
        except RuntimeError:
            return []
        return [alert.to_dict() for alert in ingest(raw, active)]

    def _run_job(
        self,
        run_id: str,
        job: ProbeJob,
        entry: RouteEntry,
        seed: SeedRequest,
        context_id: str,
    ) -> tuple[str, list[Finding], list[HeaderFinding], dict[str, int], list[ProbeAdequacy]]:
        stats = {"considered": 0, "attributed": 0, "with_header": 0, "messages": 0}
        self._set_probe_header(job.canary)
        self.api.prime_site_tree(seed.url, seed.method, seed.body, seed.content_type)
        seed_message = self.api.send_request(self._raw(seed))
        seed_header = seed_message.get("requestHeader", "")
        seed_values = request_values(seed_header, seed_message.get("requestBody", ""))
        seed_path = _path_of(seed.url)
        baseline = _response(seed_message)
        if baseline.status in _BLOCKING_STATUSES:
            blocked_code = _blocked_sub_code(baseline.status)
            rows = []
            for cwe in job.cwes:
                rows.extend(
                    _empty_adequacy(
                        job,
                        entry,
                        cwe,
                        "blocked_by_validation",
                        self.rule_ids_by_cwe.get(cwe, ()),
                        "all_blocked",
                        baseline.status,
                        blocked_code,
                    )
                )
            return "all_blocked", [], [], stats, rows
        # Header and cookie hardening is read off the clean baseline, never a
        # mutated probe response.
        headers = check_response(baseline)

        strength_key = (
            "zap.attack_strength.directed"
            if job.job_pass == "directed"
            else "zap.attack_strength.sweep"
        )
        rule_ids = sorted({r for cwe in job.cwes for r in self.rule_ids_by_cwe.get(cwe, [])})
        if not rule_ids:
            rows = []
            for cwe in job.cwes:
                rows.extend(
                    _empty_adequacy(
                        job,
                        entry,
                        cwe,
                        "untested",
                        self.rule_ids_by_cwe.get(cwe, ()),
                        "finished",
                        baseline.status,
                    )
                )
            return "finished", [], headers, stats, rows
        policy = f"elenchus-{job.job_id}"
        self.api.ensure_scan_policy(policy, rule_ids, self.config[strength_key])
        scan_id = self.api.start_scan(seed.url, seed.method, seed.body, context_id, policy)
        outcome = self._wait_for_scan(scan_id)

        candidates: dict[tuple[str, int], _Candidate] = {}
        trials: dict[tuple[str, int], list[tuple[str, int | None]]] = {}
        for message_id in self.api.scan_message_ids(scan_id):
            stats["messages"] += 1
            message = self.api.message(message_id)
            header = message.get("requestHeader", "")
            if PROBE_HEADER.casefold() in header.casefold() and job.canary in header:
                stats["with_header"] += 1
            if RULE_HEADER.casefold() not in header.casefold():
                continue  # ZAP's 404-analysis probe carries no rule header.
            stats["considered"] += 1
            found = attribute(
                header,
                message.get("requestBody", ""),
                seed_path=seed_path,
                seed_values=seed_values,
                canary=job.canary,
                rule_cwes=self.rule_cwes,
            )
            if found is None:
                continue
            stats["attributed"] += 1
            response = _response(message)
            trials.setdefault((found.param, found.cwe), []).append(
                (found.rule_id, response.status)
            )
            oracle = oracle_for(found.cwe)
            attack = _attack_value(header, message, found.param)
            if oracle is not None and oracle(baseline, response, attack):
                key = (found.param, found.cwe)
                candidates.setdefault(
                    key,
                    _Candidate(
                        found.param,
                        found.cwe,
                        attack,
                        found.rule_id,
                        message_id,
                        found.param_location,
                        found.param_path,
                    ),
                )

        findings = [
            finding
            for candidate in candidates.values()
            if (
                finding := self._verify(
                    run_id, job, seed, baseline, candidate
                )
            ) is not None
        ]
        # Boolean-based (blind) SQL that the error oracle could not confirm: try a
        # true/false replay pair per SQL param the scan did not already confirm.
        if 89 in job.cwes:
            done = {param for (param, cwe) in candidates if cwe == 89}
            boolean_findings = self._confirm_boolean(run_id, job, seed, baseline, done)
            findings.extend(boolean_findings)
            done |= {finding.param for finding in boolean_findings if finding.param}
            findings.extend(self._confirm_timing(run_id, job, seed, baseline, done))
        # Project-controlled confirmation for the injection classes ZAP's active
        # scan did not already confirm on this route. Each sends our own payloads
        # (a benign `id`, a canary tag, an external redirect host) and fires the
        # class oracle, so a reached route is confirmed deterministically rather
        # than depending on which payload ZAP happened to send.
        for cwe, payloads_for in _CONFIRM_PAYLOADS.items():
            if cwe in job.cwes:
                done_cwe = {param for (param, c) in candidates if c == cwe}
                findings.extend(
                    self._confirm_injection(
                        run_id, job, seed, baseline, cwe, oracle_for(cwe), payloads_for, done_cwe
                    )
                )
        adequacy_rows = [
            row
            for cwe in job.cwes
            for row in _parameter_adequacy(
                job,
                entry,
                cwe,
                self.rule_ids_by_cwe.get(cwe, ()),
                trials,
                outcome,
                self.enum_types,
                baseline.status,
                job.after_drift,
            )
        ]
        return outcome, findings, headers, stats, adequacy_rows

    def _verify(
        self, run_id, job, seed, baseline, candidate
    ) -> Finding | None:
        """Replay the candidate; the oracle on the replay is the verdict."""
        oracle = oracle_for(candidate.cwe)
        if oracle is None:
            return None
        attempts = self.config["replay.count"]
        fired = 0
        trace_frames: list[dict[str, Any]] = []
        for _ in range(attempts):
            replayed = self.api.send_request(
                self._replay_request(seed, candidate), follow_redirects=False
            )
            response = _response(replayed)
            if oracle(baseline, response, candidate.payload):
                fired += 1
                if self.trace_parser is not None:
                    frames = self.trace_parser(response.body)
                    if frames:
                        trace_frames = frames
        # One directed hypothesis for this (route, cwe): unique lineage. Several:
        # correlation (BS7) resolves the ambiguity, so carry them all in evidence.
        single = job.hypothesis_ids[0] if len(job.hypothesis_ids) == 1 else None
        evidence = [
            {
                "type": "ORACLE",
                "detail": {
                    "oracle": oracle.__name__,
                    "canary_id": job.canary,
                    "zap_job_id": job.job_id,
                    "zap_scan_id": job.scan_id,
                    "zap_message_id": candidate.message_id,
                    "zap_rule_id": candidate.rule_id,
                    "job_pass": job.job_pass,
                    "hypothesis_ids": list(job.hypothesis_ids),
                    "replays": attempts,
                    "fired": fired,
                    "oracle_flaky": fired < self.config["replay.min_hits"],
                    "baseline_status": baseline.status,
                },
            }
        ]
        if trace_frames:
            evidence.append(
                {"type": "RESPONSE_TRACE", "detail": {"frames": trace_frames}}
            )
        return Finding.from_dict(
            {
                "run_id": run_id,
                "source": "dast",
                "provenance": "zap",
                "cwe": candidate.cwe,
                "type": type_name(candidate.cwe),
                "route": job.route,
                "method": job.method,
                "param": candidate.param,
                "param_location": candidate.param_location,
                "param_path": candidate.param_path,
                "payload": candidate.payload,
                "hypothesis_id": single,
                "evidence": evidence,
                "severity": "high",
            }
        )

    def _wait_for_scan(self, scan_id: str) -> str:
        deadline = self._now() + self.config["probe.max_job_seconds"]
        while self.api.active_scan_status(scan_id) < 100:
            if self._now() >= deadline:
                self.api.stop_scan(scan_id)
                return "stopped_at_limit"
            self._sleep(_POLL_SECONDS)
        return "finished"

    def _drift_baselines(self, routes: tuple[RouteEntry, ...]) -> dict[str, tuple[str, Response]]:
        """Raw request and response of a sample of GET routes before scanning, so
        drift can be re-checked by replaying the exact same request. Best effort: a
        route that cannot be fetched is left out, not retried."""
        sample = [r for r in routes if r.method.upper() in _SAFE_METHODS][
            : self.config["probe.drift_routes"]
        ]
        baselines: dict[str, tuple[str, Response]] = {}
        for entry in sample:
            raw = self._raw(build_seed(entry, self.base_url))
            try:
                baselines[entry.route] = (raw, _response(self.api.send_request(raw)))
            except RuntimeError:
                continue
        return baselines

    def _drifted(self, baselines: dict[str, tuple[str, Response]]) -> bool:
        """True if any sampled GET route now answers differently than its baseline."""
        for raw, before in baselines.values():
            try:
                now = _response(self.api.send_request(raw))
            except RuntimeError:
                continue
            if (now.status, now.body) != (before.status, before.body):
                return True
        return False

    def _set_probe_header(self, canary: str) -> None:
        # The canary is "elx-...", so the probe rule is "elenchus-elx-...". Match
        # that exact prefix, not "elenchus-", so the persistent auth rule survives.
        for rule in self.api.replacer_rules():
            description = rule.get("description", "")
            if description.startswith("elenchus-elx-"):
                self.api.remove_replacer_rule(description)
        self.api.add_replacer_request_header(f"elenchus-{canary}", PROBE_HEADER, canary)

    def _set_auth_header(self) -> None:
        """A persistent Replacer rule so ZAP's own requests carry the auth header.
        Seed and replay requests add it in _raw, since core/sendRequest bypasses
        the Replacer."""
        if self._auth is not None:
            self.api.add_replacer_request_header("elenchus-auth", *self._auth)

    def _clear_auth_header(self) -> None:
        if self._auth is None:
            return
        for rule in self.api.replacer_rules():
            if rule.get("description") == "elenchus-auth":
                self.api.remove_replacer_rule("elenchus-auth")

    def _header_finding(self, run_id: str, route: str, header: HeaderFinding) -> Finding:
        return Finding.from_dict(
            {
                "run_id": run_id,
                "source": "dast",
                "provenance": "zap",
                "cwe": header.cwe,
                "type": type_name(header.cwe),
                "route": route,
                "method": "GET",
                "evidence": [
                    {
                        "type": "ORACLE",
                        "detail": {
                            "oracle": "header_check",
                            "header_name": header.header_name,
                            "detail": header.detail,
                        },
                    }
                ],
                "severity": "low",
            }
        )

    def _scope_regex(self) -> str:
        import re
        from urllib.parse import urlsplit

        parts = urlsplit(self.base_url)
        prefix = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"
        return rf"^{re.escape(prefix)}(?:/[^?#]*)?(?:\?[^#]*)?$"

    def _raw(self, seed: SeedRequest) -> str:
        from urllib.parse import urlsplit

        host = urlsplit(seed.url).netloc
        lines = [f"{seed.method} {seed.url} HTTP/1.1", f"Host: {host}"]
        if self._auth is not None:
            lines.append(f"{self._auth[0]}: {self._auth[1]}")
        if seed.content_type:
            lines.append(f"Content-Type: {seed.content_type}")
        if seed.body:
            lines.append(f"Content-Length: {len(seed.body.encode())}")
        return "\r\n".join(lines) + "\r\n\r\n" + seed.body

    def _confirm_boolean(
        self, run_id: str, job: ProbeJob, seed: SeedRequest, baseline: Response, done: set[str]
    ) -> list[Finding]:
        """Confirm blind SQL on each query param the error oracle did not confirm,
        with a true/false replay pair the project controls (sql_boolean)."""
        from urllib.parse import parse_qsl, urlsplit

        if baseline.status != 200 or not baseline.body:
            return []  # sql_boolean needs a valid, non-empty baseline to compare.
        findings: list[Finding] = []
        params = parse_qsl(urlsplit(seed.url).query, keep_blank_values=True)
        attempts = self.config["replay.count"]
        for param, value in params:
            if param in done:
                continue
            for true_suffix, false_suffix in _BOOLEAN_TEMPLATES:
                fired = 0
                for _ in range(attempts):
                    true_resp = _response(
                        self.api.send_request(
                            self._replay_request(seed, _Candidate(param, 89, value + true_suffix, "", "")),
                            follow_redirects=False,
                        )
                    )
                    false_resp = _response(
                        self.api.send_request(
                            self._replay_request(seed, _Candidate(param, 89, value + false_suffix, "", "")),
                            follow_redirects=False,
                        )
                    )
                    if sql_boolean(baseline, true_resp, false_resp):
                        fired += 1
                if fired >= self.config["replay.min_hits"]:
                    findings.append(
                        self._boolean_finding(run_id, job, param, value + true_suffix, attempts, fired)
                    )
                    break
        return findings

    def _boolean_finding(
        self, run_id: str, job: ProbeJob, param: str, payload: str, attempts: int, fired: int
    ) -> Finding:
        single = job.hypothesis_ids[0] if len(job.hypothesis_ids) == 1 else None
        return Finding.from_dict(
            {
                "run_id": run_id,
                "source": "dast",
                "provenance": "zap",
                "cwe": 89,
                "type": type_name(89),
                "route": job.route,
                "method": job.method,
                "param": param,
                "param_location": "query",
                "payload": payload,
                "hypothesis_id": single,
                "evidence": [
                    {
                        "type": "ORACLE",
                        "detail": {
                            "oracle": "sql_boolean",
                            "canary_id": job.canary,
                            "zap_job_id": job.job_id,
                            "job_pass": job.job_pass,
                            "hypothesis_ids": list(job.hypothesis_ids),
                            "replays": attempts,
                            "fired": fired,
                        },
                    }
                ],
                "severity": "high",
            }
        )

    def _confirm_injection(
        self,
        run_id: str,
        job: ProbeJob,
        seed: SeedRequest,
        baseline: Response,
        cwe: int,
        oracle: Callable[[Response, Response, str], bool] | None,
        payloads_for: Callable[[str, str], list[str]],
        done: set[str],
    ) -> list[Finding]:
        """Confirm an injection class on each query param the scan did not confirm,
        with project-controlled payloads and the class oracle. Non-vulnerable params
        cost one request (the oracle is probed once before the confirming replays)."""
        from urllib.parse import parse_qsl, urlsplit

        if oracle is None:
            return []
        params = parse_qsl(urlsplit(seed.url).query, keep_blank_values=True)
        attempts = self.config["replay.count"]
        findings: list[Finding] = []
        for param, value in params:
            if param in done:
                continue
            for payload in payloads_for(value, job.canary):
                request = self._replay_request(seed, _Candidate(param, cwe, payload, "", ""))
                if not oracle(baseline, self._replay_response(request), payload):
                    continue
                fired = 1 + sum(
                    oracle(baseline, self._replay_response(request), payload)
                    for _ in range(attempts - 1)
                )
                if fired >= self.config["replay.min_hits"]:
                    findings.append(
                        self._injection_finding(run_id, job, cwe, oracle.__name__, param, payload, attempts, fired)
                    )
                    done.add(param)
                    break
        return findings

    def _replay_response(self, raw_request: str) -> Response:
        return _response(self.api.send_request(raw_request, follow_redirects=False))

    def _injection_finding(
        self, run_id: str, job: ProbeJob, cwe: int, oracle_name: str, param: str,
        payload: str, attempts: int, fired: int,
    ) -> Finding:
        single = job.hypothesis_ids[0] if len(job.hypothesis_ids) == 1 else None
        return Finding.from_dict(
            {
                "run_id": run_id,
                "source": "dast",
                "provenance": "zap",
                "cwe": cwe,
                "type": type_name(cwe),
                "route": job.route,
                "method": job.method,
                "param": param,
                "param_location": "query",
                "payload": payload,
                "hypothesis_id": single,
                "evidence": [
                    {
                        "type": "ORACLE",
                        "detail": {
                            "oracle": oracle_name,
                            "canary_id": job.canary,
                            "zap_job_id": job.job_id,
                            "job_pass": job.job_pass,
                            "hypothesis_ids": list(job.hypothesis_ids),
                            "replays": attempts,
                            "fired": fired,
                        },
                    }
                ],
                "severity": "high",
            }
        )

    def _confirm_timing(
        self, run_id: str, job: ProbeJob, seed: SeedRequest, baseline: Response, done: set[str]
    ) -> list[Finding]:
        """Confirm time-based blind SQL on each query param not already confirmed.

        Off unless probe.timing_repeats is set. The benign baseline time is the
        median of that many replays; a payload fires when its replay is slower than
        the baseline by the threshold, reproduced replay.min_hits times."""
        from urllib.parse import parse_qsl, urlsplit

        repeats = self.config["probe.timing_repeats"]
        if not repeats or 89 not in job.cwes:
            return []
        params = parse_qsl(urlsplit(seed.url).query, keep_blank_values=True)
        if not params:
            return []
        base_median = self._median_elapsed(self._raw(seed), repeats)
        findings: list[Finding] = []
        for param, value in params:
            if param in done:
                continue
            for template in _TIMING_TEMPLATES:
                payload = value + template.format(s=_TIMING_SLEEP_SECONDS)
                request = self._replay_request(seed, _Candidate(param, 89, payload, "", ""))
                fired = sum(
                    timing_slower(
                        base_median, self._median_elapsed(request, repeats), _TIMING_THRESHOLD_SECONDS
                    )
                    for _ in range(self.config["replay.count"])
                )
                if fired >= self.config["replay.min_hits"]:
                    findings.append(
                        self._timing_finding(run_id, job, param, payload, self.config["replay.count"], fired)
                    )
                    break
        return findings

    def _median_elapsed(self, raw_request: str, repeats: int) -> float:
        from statistics import median

        samples = []
        for _ in range(max(1, repeats)):
            start = self._now()
            self.api.send_request(raw_request, follow_redirects=False)
            samples.append(self._now() - start)
        return median(samples)

    def _timing_finding(
        self, run_id: str, job: ProbeJob, param: str, payload: str, attempts: int, fired: int
    ) -> Finding:
        single = job.hypothesis_ids[0] if len(job.hypothesis_ids) == 1 else None
        return Finding.from_dict(
            {
                "run_id": run_id,
                "source": "dast",
                "provenance": "zap",
                "cwe": 89,
                "type": type_name(89),
                "route": job.route,
                "method": job.method,
                "param": param,
                "param_location": "query",
                "payload": payload,
                "hypothesis_id": single,
                "evidence": [
                    {
                        "type": "ORACLE",
                        "detail": {
                            "oracle": "timing_slower",
                            "canary_id": job.canary,
                            "zap_job_id": job.job_id,
                            "job_pass": job.job_pass,
                            "hypothesis_ids": list(job.hypothesis_ids),
                            "replays": attempts,
                            "fired": fired,
                            "threshold_seconds": _TIMING_THRESHOLD_SECONDS,
                        },
                    }
                ],
                "severity": "high",
            }
        )

    def _replay_request(self, seed: SeedRequest, candidate: _Candidate) -> str:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

        split = urlsplit(seed.url)
        query = [
            (key, candidate.payload if key == candidate.param else value)
            for key, value in parse_qsl(split.query, keep_blank_values=True)
        ]
        url = urlunsplit(split._replace(query=urlencode(query))) if query else seed.url
        return self._raw(replace(seed, url=url))


def _attack_value(request_header: str, message: dict[str, Any], param: str) -> str:
    """The decoded value ZAP put in `param`, from the query or else the body."""
    from urllib.parse import parse_qsl, urlsplit

    parts = request_header.splitlines()
    target = parts[0].split(" ")[1] if parts and len(parts[0].split(" ")) >= 2 else ""
    pairs = parse_qsl(urlsplit(target).query, keep_blank_values=True)
    if not pairs:
        pairs = parse_qsl(message.get("requestBody", ""), keep_blank_values=True)
    return next((value for key, value in pairs if key == param), "")


def _response(message: dict[str, Any]) -> Response:
    header = message.get("responseHeader", "")
    status = None
    if header:
        import re

        match = re.match(r"HTTP/\S+\s+(\d{3})", header)
        status = int(match.group(1)) if match else None
    return Response(status=status, headers=header, body=message.get("responseBody", ""))


def _path_of(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).path


def _is_loopback(host: str) -> bool:
    return host.casefold() in {"localhost", "127.0.0.1", "::1", "[::1]"}


def _blocked_sub_code(status: int | None) -> str:
    if status in {400, 422}:
        return "validation"
    if status in {401, 403}:
        return "auth"
    if status == 404:
        return "not_found"
    if status is not None and 500 <= status < 600:
        return "server_error"
    return "other"


def _empty_adequacy(
    job: ProbeJob,
    entry: RouteEntry,
    cwe: int,
    outcome: str,
    expected_rule_ids: tuple[str, ...] | list[str],
    job_outcome: str,
    baseline_status: int | None = None,
    sub_code: str | None = None,
    after_drift: bool = False,
) -> list[ProbeAdequacy]:
    return [
        ProbeAdequacy(
            job_id=job.job_id,
            route=job.route,
            method=job.method,
            cwe=cwe,
            param=param.name,
            params_status=entry.params_status,
            job_outcome=job_outcome,
            expected_rule_ids=tuple(sorted(set(expected_rule_ids))),
            observed_rule_ids=(),
            baseline_status=baseline_status,
            response_statuses=(),
            passed_validation=False,
            outcome=outcome,
            sub_code=sub_code,
            after_drift=after_drift,
        )
        for param in entry.params
    ]


def _parameter_adequacy(
    job: ProbeJob,
    entry: RouteEntry,
    cwe: int,
    expected_rule_ids: list[str] | tuple[str, ...],
    trials: dict[tuple[str, int], list[tuple[str, int | None]]],
    job_outcome: str,
    enum_types: frozenset[str],
    baseline_status: int | None,
    after_drift: bool,
) -> list[ProbeAdequacy]:
    expected = tuple(sorted(set(expected_rule_ids)))
    rows = []
    for param in entry.params:
        attempts = trials.get((param.name, cwe), [])
        observed = tuple(sorted({rule_id for rule_id, _ in attempts}))
        statuses = tuple(status for _, status in attempts)
        outcome = "untested"
        sub_code = None
        all_rules_seen = bool(expected) and set(expected).issubset(observed)
        passed_validation = any(
            status is not None and status not in _ADEQUACY_REJECTIONS
            for status in statuses
        )
        if (
            job_outcome == "finished"
            and not after_drift
            and baseline_status is not None
            and baseline_status not in _ADEQUACY_REJECTIONS
            and all_rules_seen
            and statuses
        ):
            if passed_validation:
                outcome = "adequate"
            elif all(status in _TYPE_REJECTION_STATUSES for status in statuses) and (
                _is_type_rejectable(param.java_type, enum_types)
            ):
                outcome = "type_rejected"
            elif all(status in _ADEQUACY_REJECTIONS for status in statuses):
                outcome = "blocked_by_validation"
                sub_code = _blocked_sub_code(next(iter(statuses), None))
        rows.append(
            ProbeAdequacy(
                job_id=job.job_id,
                route=job.route,
                method=job.method,
                cwe=cwe,
                param=param.name,
                params_status=entry.params_status,
                job_outcome=job_outcome,
                expected_rule_ids=expected,
                observed_rule_ids=observed,
                baseline_status=baseline_status,
                response_statuses=statuses,
                passed_validation=passed_validation,
                outcome=outcome,
                sub_code=sub_code,
                after_drift=after_drift,
            )
        )
    return rows


def _is_type_rejectable(java_type: str | None, enum_types: frozenset[str]) -> bool:
    if java_type is None:
        return False
    normalized = java_type.strip().casefold()
    return normalized in _TYPE_REJECTABLE or java_type in enum_types
