"""AI catalogue-gap proposer (Could-tier, advisory).

Recall and precision are catalogue-bound. The low-level catalogue cannot name an
app's own wrapper utilities: a method that forwards a value to a known sink, or
one that neutralises a class. This task asks the AI to propose candidate catalogue
entries for those wrappers, so recall on unseen wrappers can rise and false alarms
on sanitised safe-variants can fall.

Hard guarantees:

- No live catalogue change. The only output is a proposal file for human and CI
  review (`out/<run>/catalogue_proposals.json`).
- No finding, verdict or link is ever created from AI output.
- Off by default (`ai.enabled` and `ai.tasks.catalogue_proposer.enabled`) and off
  in judging mode.
- Every proposed symbol must resolve in the parsed index; one that names a symbol
  that does not exist is rejected.
- A proposal is tagged `accepted` only when a decoy twin shows that adding it
  flags the vulnerable twin and no safe twin. With no twin it is tagged
  `needs_human_review` and never applied.

Any accepted entry derived from a test app's results is recorded as fitted in
freeze.json and docs/STATE.md (generality rule). This module does not write the
catalogue; a reviewer does, deliberately.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from common.pipeline import CodeIndex
from producers.sast.sink_finder import Catalogue, CatalogueEntry, find_sinks
from producers.sast.spring_routes import SourceIndex, _parse_files, build_index

TASK = "catalogue_proposer"
_KINDS = {"sink", "sanitiser"}

PROPOSAL_SCHEMA = {
    "type": "object",
    "required": ["proposals"],
    "properties": {
        "proposals": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "kind", "cwe", "receiver_type", "method", "sink_arg",
                    "api_anchor", "evidence_symbol", "confidence", "rationale",
                ],
                "properties": {
                    "kind": {"type": "string"},
                    "cwe": {"type": "integer"},
                    "receiver_type": {"type": "string"},
                    "method": {"type": "string"},
                    "sink_arg": {"type": "integer"},
                    "api_anchor": {"type": "string"},
                    "evidence_symbol": {"type": "string"},
                    "confidence": {"type": "number"},
                    "rationale": {"type": "string"},
                },
            },
        }
    },
}


@dataclass(frozen=True)
class Proposal:
    kind: str  # "sink" or "sanitiser"
    cwe: int
    receiver_type: str
    method: str
    sink_arg: int
    api_anchor: str
    evidence_symbol: str
    confidence: float
    rationale: str

    @classmethod
    def from_dict(cls, raw: dict) -> Proposal:
        return cls(
            kind=str(raw["kind"]),
            cwe=int(raw["cwe"]),
            receiver_type=str(raw["receiver_type"]),
            method=str(raw["method"]),
            sink_arg=int(raw["sink_arg"]),
            api_anchor=str(raw["api_anchor"]),
            evidence_symbol=str(raw["evidence_symbol"]),
            confidence=float(raw["confidence"]),
            rationale=str(raw["rationale"]),
        )

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "cwe": self.cwe,
            "receiver_type": self.receiver_type,
            "method": self.method,
            "sink_arg": self.sink_arg,
            "api_anchor": self.api_anchor,
            "evidence_symbol": self.evidence_symbol,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ReviewedProposal:
    proposal: Proposal
    status: str  # "accepted", "needs_human_review" or "rejected:<reason>"

    def to_dict(self) -> dict:
        return {**self.proposal.to_dict(), "status": self.status}


@dataclass(frozen=True)
class Twin:
    """A decoy pair for one CWE: a vulnerable source tree and its safe variant."""

    cwe: int
    vulnerable_root: Path
    safe_root: Path


def wrapper_candidates(index: CodeIndex) -> list[dict]:
    """Unresolved-receiver call sites that drop out of strict sink detection.

    These are where an app wrapper likely hides a known sink or a sanitiser. The
    call graph keeps them flagged; the AI names a real receiver type for them."""
    seen: dict[tuple[str, str, int], dict] = {}
    for edge in index.call_graph:
        if edge.resolved:
            continue
        key = (edge.callee, edge.file, edge.line)
        seen.setdefault(
            key,
            {"method": edge.callee, "file": edge.file, "line": edge.line, "caller": edge.caller},
        )
    return sorted(seen.values(), key=lambda c: (c["file"], c["line"], c["method"]))


def propose(
    index: CodeIndex,
    source_index: SourceIndex,
    catalogue: Catalogue,
    client,
    twins: Sequence[Twin] = (),
) -> list[ReviewedProposal]:
    """Ask the AI for catalogue entries and review each one. Returns [] when the
    task is off, the client is unavailable, there are no wrapper candidates, or the
    AI makes no valid reply."""
    if client is None or not client.available(TASK):
        return []
    candidates = wrapper_candidates(index)
    if not candidates:
        return []
    answer = client.complete(TASK, _prompt(candidates, source_index, catalogue), PROPOSAL_SCHEMA)
    if answer is None:
        return []
    return [
        _review(Proposal.from_dict(raw), source_index, catalogue, twins)
        for raw in answer["proposals"]
    ]


def write_proposals(reviewed: Sequence[ReviewedProposal], path: Path) -> None:
    payload = {
        "task": TASK,
        "note": (
            "Advisory only. No entry here is live. A reviewer applies an accepted "
            "entry to the catalogue deliberately and records it as fitted."
        ),
        "accepted": [r.to_dict() for r in reviewed if r.status == "accepted"],
        "needs_human_review": [r.to_dict() for r in reviewed if r.status == "needs_human_review"],
        "rejected": [r.to_dict() for r in reviewed if r.status.startswith("rejected")],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def augment(catalogue: Catalogue, proposals: Sequence[Proposal]) -> Catalogue:
    """A copy of the catalogue with the proposals added, for a dry run only. The
    on-disk catalogue is never touched."""
    entries = list(catalogue.entries)
    sanitisers = set(catalogue.sanitisers)
    for i, proposal in enumerate(proposals):
        if proposal.kind == "sink":
            type_name, severity = _type_meta(catalogue, proposal.cwe)
            entries.append(
                CatalogueEntry(
                    entry_id=f"ai-proposed-{proposal.receiver_type}-{proposal.method}-{i}",
                    api=proposal.api_anchor,
                    kind="call",
                    receiver_types=frozenset({proposal.receiver_type}),
                    methods=frozenset({proposal.method}),
                    sink_arg=proposal.sink_arg,
                    cwe=proposal.cwe,
                    type_name=type_name,
                    severity=severity,
                )
            )
        elif proposal.kind == "sanitiser":
            sanitisers.add((proposal.receiver_type, proposal.method))
    return Catalogue(tuple(entries), frozenset(sanitisers))


def _review(proposal, source_index, catalogue, twins) -> ReviewedProposal:
    if proposal.kind not in _KINDS:
        return ReviewedProposal(proposal, "rejected:unknown_kind")
    if not _symbol_exists(source_index, proposal.receiver_type, proposal.method):
        return ReviewedProposal(proposal, "rejected:symbol_unreal")
    passed = _passes_twin(proposal, twins, catalogue)
    if passed is None:
        return ReviewedProposal(proposal, "needs_human_review")
    if not passed:
        return ReviewedProposal(proposal, "rejected:twin_failed")
    return ReviewedProposal(proposal, "accepted")


def _symbol_exists(source_index: SourceIndex, receiver_type: str, method: str) -> bool:
    infos = source_index.types.get(receiver_type)
    return bool(infos) and any(method in info["methods"] for info in infos)


def _type_meta(catalogue: Catalogue, cwe: int) -> tuple[str, str]:
    for entry in catalogue.entries:
        if entry.cwe == cwe:
            return entry.type_name, entry.severity
    return f"CWE-{cwe}", "high"


def _passes_twin(proposal, twins, catalogue) -> bool | None:
    """True/False from the decoy twins for this CWE, or None when none is given.

    A sink proposal must add a detection in the vulnerable twin and add none in the
    safe twin. A sanitiser proposal must clear a detection in the safe twin and
    clear none in the vulnerable twin."""
    relevant = [twin for twin in twins if twin.cwe == proposal.cwe]
    if not relevant:
        return None
    augmented = augment(catalogue, [proposal])
    for twin in relevant:
        vuln = _sink_ids(twin.vulnerable_root, catalogue, augmented)
        safe = _sink_ids(twin.safe_root, catalogue, augmented)
        if proposal.kind == "sink":
            if not (vuln.augmented - vuln.base) or (safe.augmented - safe.base):
                return False
        else:  # sanitiser
            if not (safe.base - safe.augmented) or (vuln.base - vuln.augmented):
                return False
    return True


@dataclass(frozen=True)
class _SinkDiff:
    base: set
    augmented: set


def _sink_ids(root: Path, base: Catalogue, augmented: Catalogue) -> _SinkDiff:
    """Dynamic-argument sink sites only. A constant or sanitised argument is
    suppressed downstream, so it is not a "flag"; the twin test turns on the sites
    that would actually be reported."""
    index = build_index(_parse_files(root))
    return _SinkDiff(
        base=_dynamic_sites(index, base),
        augmented=_dynamic_sites(index, augmented),
    )


def _dynamic_sites(index: SourceIndex, catalogue: Catalogue) -> set:
    return {
        site.sink_id for site in find_sinks(index, catalogue) if site.arg_shape == "dynamic"
    }


def _prompt(candidates: Sequence[dict], source_index: SourceIndex, catalogue: Catalogue) -> str:
    methods = sorted({c["method"] for c in candidates})[:40]
    types = sorted(source_index.types)[:80]
    known = sorted(catalogue.method_names)
    return (
        "A static sink finder matches a call's name and receiver type against a "
        "low-level catalogue; there is no dataflow. The call sites below did not "
        "resolve to a known sink. Some may be app wrappers that forward a value to a "
        "known sink, or app methods that neutralise a class (a sanitiser).\n\n"
        f"Unresolved call method names: {', '.join(methods) or '(none)'}.\n"
        f"Types declared in the app: {', '.join(types) or '(none)'}.\n"
        f"Known low-level sink methods: {', '.join(known)}.\n\n"
        "Propose catalogue entries. Use kind=sink for a wrapper that forwards a "
        "value to a known sink, kind=sanitiser for a method that neutralises a "
        "class. receiver_type MUST be a type declared in the app above and method "
        "MUST be one that type declares. sink_arg is the zero-based position of the "
        "argument carrying the dangerous value. api_anchor names the low-level API "
        "the wrapper reaches. evidence_symbol is the file:line it was seen at.\n\n"
        'Reply with JSON {"proposals": [{"kind", "cwe", "receiver_type", "method", '
        '"sink_arg", "api_anchor", "evidence_symbol", "confidence", "rationale"}]}. '
        "Propose nothing you cannot ground in a real declared symbol."
    )
