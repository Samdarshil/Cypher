"""Flag verification.

Negative marking means a false CONFIRMED is worse than a slow NOT_YET_FOUND.
A candidate only reaches CONFIRMED if it passes every check below. There is
no path from "the LLM asserts this is the flag" straight to CONFIRMED —
the string must be traceable to real tool output stored in the evidence
store.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from cypher.evidence.models import EvidenceStore
from cypher.flags.extractor import FlagCandidate


class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    UNCONFIRMED = "UNCONFIRMED"


@dataclass
class VerificationResult:
    status: VerificationStatus
    candidate: FlagCandidate
    evidence_ids: list[str]
    reason: str

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "full_flag": self.candidate.full_match,
            "flag_value": self.candidate.inner_value,
            "evidence_ids": self.evidence_ids,
            "reason": self.reason,
            "method": self.candidate.method_hint,
        }


class FlagVerifier:
    def __init__(self, evidence_store: EvidenceStore, min_relevance: float = 0.3) -> None:
        self.evidence_store = evidence_store
        self.min_relevance = min_relevance

    def verify(self, candidate: FlagCandidate) -> VerificationResult:
        # 1. Format validation happened at extraction time (regex match).

        # 2. Source validation: does this string literally exist in at
        #    least one stored raw tool-output file? This is the anti-
        #    hallucination check — an LLM claiming a flag isn't enough.
        hits = self.evidence_store.search_raw(candidate.full_match)
        if not hits:
            return VerificationResult(
                status=VerificationStatus.UNCONFIRMED,
                candidate=candidate,
                evidence_ids=[],
                reason="Candidate does not appear verbatim in any stored tool output.",
            )

        evidence_ids = [e.id for e in hits]

        # 3. Context validation: is the supporting evidence itself marked
        #    as reasonably relevant, rather than incidental noise?
        best_relevance = max(e.relevance for e in hits)
        if best_relevance < self.min_relevance:
            return VerificationResult(
                status=VerificationStatus.PROBABLE,
                candidate=candidate,
                evidence_ids=evidence_ids,
                reason=(
                    f"Found in tool output but source relevance ({best_relevance:.2f}) "
                    f"is below confirmation threshold ({self.min_relevance})."
                ),
            )

        # 4. Independent confirmation. For most transformations, a single
        #    real source is enough — but single-byte XOR is brute-forced
        #    across 255 keys (tools/crypto/scripts/auto_decode.py), so a
        #    coincidental flag-shaped match is a real risk: with enough
        #    keys tried against real byte content, "looks like a flag"
        #    can happen by chance on an unrelated key. Requiring a second
        #    independent piece of evidence for brute-force-derived
        #    candidates specifically (not for deterministic single-guess
        #    transforms like base64/hex, which stay single-source-
        #    confirmable) closes that gap without touching anything else.
        distinct_tools = {e.source_tool for e in hits}
        is_bruteforced = bool(candidate.method_hint) and candidate.method_hint.startswith("xor-")
        corroborated = len(distinct_tools) > 1 or len(hits) > 1

        if is_bruteforced and not corroborated:
            return VerificationResult(
                status=VerificationStatus.PROBABLE,
                candidate=candidate,
                evidence_ids=evidence_ids,
                reason=(
                    f"Matches flag format via brute-forced single-byte XOR "
                    f"({candidate.method_hint}) but appears in only one evidence "
                    f"source. Brute force over 255 keys can produce a coincidental "
                    f"flag-shaped match; requires independent corroboration (a "
                    f"second tool or evidence source) before CONFIRMED."
                ),
            )

        reason = (
            f"Found verbatim in output of tool(s): {', '.join(sorted(distinct_tools))}."
        )
        if candidate.method_hint:
            reason += f" Recovered via transformation: {candidate.method_hint}."
        if len(distinct_tools) > 1:
            reason += " Independently corroborated by multiple tools."

        return VerificationResult(
            status=VerificationStatus.CONFIRMED,
            candidate=candidate,
            evidence_ids=evidence_ids,
            reason=reason,
        )
