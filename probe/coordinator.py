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
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from common.config import Config
from common.pipeline import Hypothesis, ProbeJob, SeedRequest
from common.record import Finding, RouteEntry
from common.vocabulary import type_name
from probe.attribution import PROBE_HEADER, RULE_HEADER, attribute, request_values
from probe.oracles import Response, oracle_for
from probe.preflight import ContextPath
from probe.seeds import build_seed

# ZAP input-vector bitmask: query string (1) and POST data (2). The URL-path
# vector stays off here; a path-param sink needs the scoped handling added in BS6.
_INJECTABLE_QUERY_AND_BODY = "3"
_POLL_SECONDS = 0.5
_BLOCKING_STATUSES = range(400, 600)


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
    foreign_hosts: list[str] = field(default_factory=list)


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
    def __init__(self, api: ZapApiLike, config: Config, base_url: str, context: ContextPath) -> None:
        self.api = api
        self.config = config
        self.base_url = base_url.rstrip("/")
        self.context = context
        self.rule_cwes = {rule: cwe for cwe, rules in config.rule_map().items() for rule in rules}
        self.rule_ids_by_cwe = config.rule_map()
        self._sleep = time.sleep
        self._now = time.monotonic

    def run(self, run_id: str, jobs: list[ProbeJob], routes: tuple[RouteEntry, ...]) -> ProbeResult:
        entries = {(r.route, r.method): r for r in routes}
        context_id = self.api.create_context(f"elenchus-{run_id}", self._scope_regex())
        findings: list[Finding] = []
        executed: list[ProbeJob] = []
        attributed = 0
        considered = 0
        with_header = 0
        total_messages = 0
        try:
            self.api.set_option("ascan", "InjectPluginIdInHeader", "Boolean", "true")
            self.api.set_option(
                "ascan", "ThreadPerHost", "Integer", str(self.config["zap.thread_per_host"])
            )
            self.api.set_option(
                "ascan", "TargetParamsInjectable", "Integer", _INJECTABLE_QUERY_AND_BODY
            )
            for job in jobs:
                entry = entries[(job.route, job.method)]
                seed = build_seed(entry, self.base_url)
                outcome, job_findings, stats = self._run_job(run_id, job, seed, context_id)
                executed.append(replace(job, seed_request=seed, outcome=outcome))
                findings.extend(job_findings)
                considered += stats["considered"]
                attributed += stats["attributed"]
                with_header += stats["with_header"]
                total_messages += stats["messages"]
            foreign = [host for host in self.api.hosts() if not _is_loopback(host)]
        finally:
            self.api.remove_context(f"elenchus-{run_id}")
        return ProbeResult(
            findings=findings,
            jobs=executed,
            attribution_rate=(attributed / considered) if considered else 1.0,
            header_propagation_rate=(with_header / total_messages) if total_messages else 1.0,
            foreign_hosts=foreign,
        )

    def _run_job(
        self, run_id: str, job: ProbeJob, seed: SeedRequest, context_id: str
    ) -> tuple[str, list[Finding], dict[str, int]]:
        stats = {"considered": 0, "attributed": 0, "with_header": 0, "messages": 0}
        self._set_probe_header(job.canary)
        self.api.prime_site_tree(seed.url, seed.method, seed.body, seed.content_type)
        seed_message = self.api.send_request(self._raw(seed))
        seed_header = seed_message.get("requestHeader", "")
        seed_values = request_values(seed_header, seed_message.get("requestBody", ""))
        seed_path = _path_of(seed.url)
        baseline = _response(seed_message)
        if baseline.status in _BLOCKING_STATUSES:
            return "all_blocked", [], stats

        rule_ids = sorted({r for cwe in job.cwes for r in self.rule_ids_by_cwe.get(cwe, [])})
        if not rule_ids:
            return "finished", [], stats
        policy = f"elenchus-{job.job_id}"
        self.api.ensure_scan_policy(policy, rule_ids, self.config["zap.attack_strength.directed"])
        scan_id = self.api.start_scan(seed.url, seed.method, seed.body, context_id, policy)
        outcome = self._wait_for_scan(scan_id)

        candidates: dict[tuple[str, int], _Candidate] = {}
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
            oracle = oracle_for(found.cwe)
            attack = _attack_value(header, message, found.param)
            if oracle is not None and oracle(baseline, _response(message), attack):
                key = (found.param, found.cwe)
                candidates.setdefault(
                    key,
                    _Candidate(found.param, found.cwe, attack, found.rule_id, message_id),
                )

        findings = [
            finding
            for candidate in candidates.values()
            if (finding := self._verify(run_id, job, seed, seed_path, seed_values, baseline, candidate))
            is not None
        ]
        return outcome, findings, stats

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
        for rule in self.api.replacer_rules():
            description = rule.get("description", "")
            if description.startswith("elenchus-"):
                self.api.remove_replacer_rule(description)
        self.api.add_replacer_request_header(f"elenchus-{canary}", PROBE_HEADER, canary)

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
