"""BS0: check the ZAP behaviour the probe design relies on.

Throwaway acceptance check, not pipeline code. See "ZAP acceptance check" in
docs/architecture.md. It scans only the loopback VulnerableApp started from
infra/vulnerableapp.compose.yaml, through the API of infra/zap.compose.yaml.

    export ZAP_API_KEY=<the key ZAP was started with>
    uv run python scripts/bs0_zap_check.py --output out/bs0/results.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.record import LOCALHOST_NAMES
from producers.dast.zap_runner import ZapApi

CONTEXT = "elenchus-bs0"
PROBE_HEADER = "X-Elenchus-Probe"
RULE_HEADER = "X-ZAP-Scan-ID"
JOB_LIMIT_SECONDS = 150
POLL_SECONDS = 0.5
EXCLUDE_PREFIX = "^"

RULE_MAP = {
    89: ["40018"],
    79: ["40012"],
    78: ["90020"],
    601: ["20019"],
    22: ["6"],
}
SQL_TIME_RULES = ["40019", "40020", "40021", "40022", "40027"]

# Input locations: query=1, post=2, url path=16. The URL path vector mutates every
# segment, including the context path, so it stays off unless a job needs it.
QUERY_AND_BODY = 1 | 2
URL_PATH = 16
URL_PATH_PARAM_TYPE = "16"


@dataclass(frozen=True)
class Job:
    name: str
    cwe: int
    path: str
    method: str = "GET"
    body: str = ""
    content_type: str = ""
    injectable: int = QUERY_AND_BODY
    only_path_value: str = ""


LOCATION_JOBS = (
    Job("query", 89, "/ErrorBasedSQLInjectionVulnerability/LEVEL_1?id=1"),
    Job(
        "form",
        89,
        "/AuthenticationVulnerability/LEVEL_9",
        "POST",
        "username=admin&password=x",
        "application/x-www-form-urlencoded",
    ),
    Job(
        "json",
        89,
        "/PasswordResetVulnerability/LEVEL_1",
        "POST",
        '{"action":"request","email":"a@example.test"}',
        "application/json",
    ),
    Job("path_unscoped", 89, "/contentDispositionUpload/x.txt", injectable=URL_PATH),
    Job(
        "path_scoped",
        89,
        "/contentDispositionUpload/x.txt",
        injectable=URL_PATH,
        only_path_value="x.txt",
    ),
)
TIMING_JOBS = (
    Job("sqli", 89, "/ErrorBasedSQLInjectionVulnerability/LEVEL_1?id=1"),
    Job("xss", 79, "/XSSWithHtmlTagInjection/LEVEL_1?value=elenchus"),
    Job("cmd", 78, "/CommandInjection/LEVEL_1?ipaddress=127.0.0.1"),
    Job("redirect", 601, "/Http3xxStatusCodeBasedInjection/LEVEL_1?returnTo=/x"),
    Job("traversal", 22, "/PathTraversal/LEVEL_1?fileName=UserInfo.json"),
)


def split_request(header: str, body: str) -> tuple[str, dict[str, str]]:
    target = header.splitlines()[0].split(" ")[1]
    parts = urllib.parse.urlsplit(target)
    values = {f"path[{i}]": s for i, s in enumerate(parts.path.split("/")) if s}
    values.update(
        {f"query.{k}": v for k, v in urllib.parse.parse_qsl(parts.query, True)}
    )
    if not body:
        return parts.path, values
    if body.lstrip().startswith("{"):
        try:
            decoded = json.loads(body)
        except json.JSONDecodeError:
            values["body"] = body
        else:
            values.update({f"json.{k}": json.dumps(v) for k, v in decoded.items()})
    else:
        pairs = urllib.parse.parse_qsl(body, True)
        values.update({f"form.{k}": v for k, v in pairs} or {"body": body})
    return parts.path, values


def changed_params(seed: dict[str, str], request: dict[str, str]) -> list[str]:
    return sorted(
        key
        for key in seed.keys() | request.keys()
        if seed.get(key) != request.get(key)
    )


def header_value(header: str, name: str) -> str | None:
    for line in header.splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip().casefold() == name.casefold():
            return value.strip()
    return None


def status_of(response_header: str) -> int | None:
    match = re.match(r"HTTP/\S+\s+(\d{3})", response_header)
    return int(match.group(1)) if match else None


class Check:
    def __init__(self, api: ZapApi, base_url: str) -> None:
        self.api = api
        self.base_url = base_url.rstrip("/")
        self.base_path = urllib.parse.urlsplit(self.base_url).path
        self.origin = self.base_url.removesuffix(self.base_path)

    def setup(self) -> str:
        self.api.call("ascan", "action", "setOptionInjectPluginIdInHeader", {"Boolean": "true"})
        self.api.call("ascan", "action", "setOptionThreadPerHost", {"Integer": "2"})
        escaped = re.escape(self.base_path)
        return self.api.create_context(
            CONTEXT, rf"^{re.escape(self.origin)}{escaped}(?:/[^?#]*)?(?:\?[^#]*)?$"
        )

    def policy(self, name: str, strength: str, rule_ids: list[str]) -> None:
        policies = self.api.call("ascan", "view", "scanPolicyNames").get("scanPolicyNames", [])
        if name in policies:
            self.api.call("ascan", "action", "removeScanPolicy", {"scanPolicyName": name})
        self.api.call(
            "ascan",
            "action",
            "addScanPolicy",
            {"scanPolicyName": name, "attackStrength": strength, "alertThreshold": "MEDIUM"},
        )
        self.api.call("ascan", "action", "disableAllScanners", {"scanPolicyName": name})
        self.api.call(
            "ascan", "action", "enableScanners", {"ids": ",".join(rule_ids), "scanPolicyName": name}
        )
        for rule_id in rule_ids:
            self.api.call(
                "ascan",
                "action",
                "setScannerAttackStrength",
                {"id": rule_id, "attackStrength": strength, "scanPolicyName": name},
            )

    def set_probe_rule(self, canary: str) -> None:
        for rule in self.api.call("replacer", "view", "rules")["rules"]:
            if rule["description"].startswith("elenchus-"):
                self.api.call(
                    "replacer", "action", "removeRule", {"description": rule["description"]}
                )
        self.api.call(
            "replacer",
            "action",
            "addRule",
            {
                "description": f"elenchus-{canary}",
                "enabled": "true",
                "matchType": "REQ_HEADER",
                "matchRegex": "false",
                "matchString": PROBE_HEADER,
                "replacement": canary,
                "initiators": "",
            },
        )

    def raw_request(self, job: Job, follow: bool = False) -> dict[str, Any]:
        url = f"{self.base_url}{job.path}"
        parts = urllib.parse.urlsplit(url)
        lines = [f"{job.method} {url} HTTP/1.1", f"Host: {parts.netloc}"]
        if job.content_type:
            lines.append(f"Content-Type: {job.content_type}")
        if job.body:
            lines.append(f"Content-Length: {len(job.body.encode())}")
        raw = "\r\n".join(lines) + "\r\n\r\n" + job.body
        result = self.api.call(
            "core",
            "action",
            "sendRequest",
            {"request": raw, "followRedirects": str(follow).lower()},
        )
        return result["sendRequest"][0]

    def seed_through_proxy(self, job: Job) -> None:
        # sendRequest does not add a POST to the site tree. Proxied traffic does,
        # and an active scan can only start from a node in the tree.
        proxy = urllib.request.ProxyHandler({"http": self.api.base_url})
        opener = urllib.request.build_opener(proxy)
        headers = {"Content-Type": job.content_type} if job.content_type else {}
        request = urllib.request.Request(
            f"{self.base_url}{job.path}",
            data=job.body.encode() if job.body else None,
            headers=headers,
            method=job.method,
        )
        try:
            with opener.open(request, timeout=20) as response:
                response.read()
        except urllib.error.HTTPError as error:
            error.read()

    def set_inputs(self, job: Job) -> None:
        self.api.call(
            "ascan", "action", "setOptionTargetParamsInjectable", {"Integer": str(job.injectable)}
        )
        params = self.api.call("ascan", "view", "excludedParams")["excludedParams"]
        for param in reversed(params):
            if param["parameter"].startswith(EXCLUDE_PREFIX):
                self.api.call("ascan", "action", "removeExcludedParam", {"idx": param["idx"]})
        if job.only_path_value:
            value = re.escape(job.only_path_value)
            self.api.call(
                "ascan",
                "action",
                "addExcludedParam",
                {"name": f"{EXCLUDE_PREFIX}(?!{value}$).*$", "type": URL_PATH_PARAM_TYPE, "url": "*"},
            )

    def run_job(self, job: Job, policy: str, context_id: str) -> dict[str, Any]:
        canary = f"elx-{job.name}-{int(time.time() * 1000)}"
        self.set_probe_rule(canary)
        self.set_inputs(job)
        self.seed_through_proxy(job)
        seed_message = self.raw_request(job)
        url = f"{self.base_url}{job.path}"
        seed_path, seed = split_request(seed_message["requestHeader"], seed_message["requestBody"])
        started = time.monotonic()
        scan_id = self.api.call(
            "ascan",
            "action",
            "scan",
            {
                "url": url,
                "recurse": "false",
                "method": job.method,
                "postData": job.body,
                "contextId": context_id,
                "scanPolicyName": policy,
            },
        )["scan"]
        stopped = False
        while self.api.active_scan_status(scan_id) < 100:
            if time.monotonic() - started > JOB_LIMIT_SECONDS:
                self.api.call("ascan", "action", "stop", {"scanId": scan_id})
                stopped = True
                break
            time.sleep(POLL_SECONDS)
        seconds = round(time.monotonic() - started, 1)
        ids = self.api.call("ascan", "view", "messagesIds", {"scanId": scan_id})["messagesIds"]
        record: dict[str, Any] = {
            "job": job.name,
            "cwe": job.cwe,
            "scan_id": scan_id,
            "seconds": seconds,
            "stopped_at_limit": stopped,
            "messages": len(ids),
            "with_probe_header": 0,
            "with_right_canary": 0,
            "with_rule_header": 0,
            "rules": {},
            "paths": {},
            "off_route": 0,
            "changed": {"none": 0, "one": 0, "many": 0},
            "changed_params": {},
            "statuses": {},
            "ids": ids,
        }
        for message_id in ids:
            message = self.api.message(message_id)
            header = message["requestHeader"]
            probe = header_value(header, PROBE_HEADER)
            record["with_probe_header"] += probe is not None
            record["with_right_canary"] += probe == canary
            rule = header_value(header, RULE_HEADER)
            record["with_rule_header"] += rule is not None
            record["rules"][rule or "none"] = record["rules"].get(rule or "none", 0) + 1
            path, values = split_request(header, message["requestBody"])
            record["paths"][path] = record["paths"].get(path, 0) + 1
            record["off_route"] += path != seed_path
            changed = changed_params(seed, values)
            bucket = "none" if not changed else "one" if len(changed) == 1 else "many"
            record["changed"][bucket] += 1
            for name in changed:
                record["changed_params"][name] = record["changed_params"].get(name, 0) + 1
            status = status_of(message["responseHeader"])
            record["statuses"][str(status)] = record["statuses"].get(str(status), 0) + 1
        alerts = self.api.call("ascan", "view", "alertsIds", {"scanId": scan_id}).get("alertsIds", [])
        record["alerts"] = len(alerts)
        return record


def run(api: ZapApi, base_url: str) -> dict[str, Any]:
    check = Check(api, base_url)
    results: dict[str, Any] = {}
    results["version"] = api.call("core", "view", "version")["version"]
    available = {r["id"]: r["name"] for r in api.call("ascan", "view", "scanners")["scanners"]}
    wanted = [i for ids in RULE_MAP.values() for i in ids] + SQL_TIME_RULES
    results["check_6_rules"] = {i: available.get(i, "MISSING") for i in wanted}
    context_id = check.setup()
    try:
        results["jobs_by_location"] = []
        for job in LOCATION_JOBS:
            print(f"location job: {job.name}", file=sys.stderr, flush=True)
            check.policy("elenchus-loc", "LOW", RULE_MAP[job.cwe])
            results["jobs_by_location"].append(check.run_job(job, "elenchus-loc", context_id))

        results["timing"] = []
        for strength in ("LOW", "MEDIUM"):
            for job in TIMING_JOBS:
                print(f"timing job: {job.name} {strength}", file=sys.stderr, flush=True)
                name = f"elenchus-{job.name}-{strength.lower()}"
                check.policy(name, strength, RULE_MAP[job.cwe])
                record = check.run_job(job, name, context_id)
                record["strength"] = strength
                results["timing"].append(record)

        print("timing job: sqli time-based rules", file=sys.stderr, flush=True)
        check.policy("elenchus-sqlt", "LOW", SQL_TIME_RULES)
        record = check.run_job(TIMING_JOBS[0], "elenchus-sqlt", context_id)
        record["strength"] = "LOW, time-based rules"
        results["timing"].append(record)

        redirect = Job("replay", 601, "/Http3xxStatusCodeBasedInjection/LEVEL_1?returnTo=http://elenchus.invalid/x")
        check.set_probe_rule("elx-replay")
        no_follow = check.raw_request(redirect, follow=False)
        results["check_5_replay"] = {
            "status": status_of(no_follow["responseHeader"]),
            "location": header_value(no_follow["responseHeader"], "Location"),
            "probe_header": header_value(no_follow["requestHeader"], PROBE_HEADER),
        }
        results["check_8_hosts"] = api.call("core", "view", "hosts")["hosts"]
    finally:
        api.remove_context(CONTEXT)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:9090/VulnerableApp")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if urllib.parse.urlsplit(args.base_url).hostname not in LOCALHOST_NAMES:
        parser.error("the target must be on localhost")
    results = run(ZapApi.from_environment(), args.base_url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2))
    print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
