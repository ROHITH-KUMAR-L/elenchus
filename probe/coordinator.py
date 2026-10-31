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
from probe.oracles import Response, oracle_for
from probe.preflight import ContextPath
from probe.scheduler import run_two_pass
from probe.seeds import build_seed

# ZAP input-vector bitmask: query string (1) and POST data (2). The URL-path
# vector stays off here; a path-param sink needs the scoped handling added in BS6.
_INJECTABLE_QUERY_AND_BODY = "3"
_POLL_SECONDS = 0.5
_BLOCKING_STATUSES = range(400, 600)
_ADEQUACY_REJECTIONS = {400, 401, 403, 404, 422}
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
        self._sleep = time.sleep
        self._now = time.monotonic
        self.enum_types = enum_types
        self.trace_parser = trace_parser

    def run(self, run_id: str, jobs: list[ProbeJob], routes: tuple[RouteEntry, ...]) -> ProbeResult:
        entries = {(r.route, r.method): r for r in routes}
        context_id = self.api.create_context(f"elenchus-{run_id}", self._scope_regex())
        findings: list[Finding] = []
        adequacy: list[ProbeAdequacy] = []
        totals = {"considered": 0, "attributed": 0, "with_header": 0, "messages": 0}
        # One finding per missing protection across the whole app (per_app dedupe).
        header_hits: dict[tuple[int, str], tuple[str, HeaderFinding]] = {}
        start = self._now()
        try:
            self._set_auth_header()
            self.api.set_option("ascan", "InjectPluginIdInHeader", "Boolean", "true")
            self.api.set_option(
                "ascan", "ThreadPerHost", "Integer", str(self.config["zap.thread_per_host"])
            )
            self.api.set_option(
                "ascan", "TargetParamsInjectable", "Integer", _INJECTABLE_QUERY_AND_BODY
            )

            def run_one(job: ProbeJob) -> ProbeJob:
                entry = entries[(job.route, job.method)]
                seed = build_seed(entry, self.base_url)
                # One job's ZAP failure (a stalled or rejected API call) must not
                # abort the run: record it as errored and move on, so the budget
                # and the other jobs still hold.
                try:
                    outcome, job_findings, headers, stats, job_adequacy = self._run_job(
                        run_id, job, entry, seed, context_id
                    )
                except RuntimeError:
                    return replace(job, seed_request=seed, outcome="errored")
                findings.extend(job_findings)
                adequacy.extend(job_adequacy)
                for key in totals:
                    totals[key] += stats[key]
                for header in headers:
                    header_hits.setdefault((header.cwe, header.header_name), (job.route, header))
                return replace(job, seed_request=seed, outcome=outcome)

            schedule = run_two_pass(
                jobs, self.config["probe.stage_budget_seconds.zap_jobs"], self._now, run_one
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
        )

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
                    _Candidate(found.param, found.cwe, attack, found.rule_id, message_id),
                )

        findings = [
            finding
            for candidate in candidates.values()
            if (
                finding := self._verify(
                    run_id, job, seed, seed_path, seed_values, baseline, candidate
                )
            ) is not None
        ]
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
        self, run_id, job, seed, seed_path, seed_values, baseline, candidate
    ) -> Finding | None:
        """Replay the candidate; the oracle on the replay is the verdict."""
        oracle = oracle_for(candidate.cwe)
        if oracle is None:
            return None
        attempts = self.config["replay.count"]
        fired = 0
        for _ in range(attempts):
            replayed = self.api.send_request(
                self._replay_request(seed, candidate), follow_redirects=False
            )
            if oracle(baseline, _response(replayed), candidate.payload):
                fired += 1
        if fired < self.config["replay.min_hits"]:
            return None  # Not reproduced: no record. oracle_flaky lives in the log only.
        # One directed hypothesis for this (route, cwe): unique lineage. Several:
        # correlation (BS7) resolves the ambiguity, so carry them all in evidence.
        single = job.hypothesis_ids[0] if len(job.hypothesis_ids) == 1 else None
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
                "payload": candidate.payload,
                "hypothesis_id": single,
                "evidence": [
                    {
                        "type": "ORACLE",
                        "detail": {
                            "oracle": oracle.__name__,
                            "canary_id": job.canary,
                            "zap_job_id": job.job_id,
                            "zap_scan_id": job.scan_id,
                            "zap_message_id": candidate.message_id,
                            "zap_rule_id": candidate.rule_id,
                            "hypothesis_ids": list(job.hypothesis_ids),
                            "replays": attempts,
                            "fired": fired,
                            "baseline_status": baseline.status,
                        },
                    }
                ],
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
