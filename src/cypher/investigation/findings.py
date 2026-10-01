"""Structured findings.

Per spec section 12: AI output must never become application state as
free-form text. Every finding is a typed object with explicit evidence
and tool-result references — if those references are empty, the finding
cannot exist (enforced in __post_init__), which is the mechanical
version of section 13's "never say X unless the evidence contains X."

Per spec section 16: a finding starts as an AI recommendation and only
becomes a confirmed investigative conclusion through an explicit human
action — nothing here auto-promotes AI output to "confirmed".
"""
from __future__ import annotations

import itertools
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewState(str, Enum):
    AI_PROPOSED = "ai_proposed"       # not yet reviewed by a human
    HUMAN_CONFIRMED = "human_confirmed"
    HUMAN_REJECTED = "human_rejected"
    NEEDS_REVIEW = "needs_review"      # human explicitly flagged, undecided


class InsufficientEvidenceError(RuntimeError):
    pass


@dataclass
class Finding:
    finding_id: str            # "F-0001"
    title: str
    severity: Severity
    confidence: float          # 0..1 -- the AI's stated confidence, not a guarantee
    summary: str
    reasoning: str
    evidence_refs: list[str] = field(default_factory=list)      # EVID-XXXX ids
    tool_result_refs: list[str] = field(default_factory=list)   # evidence-store ids
    review_state: ReviewState = ReviewState.AI_PROPOSED
    analyst_note: str | None = None   # human-added note (confirm/reject/review reason)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.evidence_refs and not self.tool_result_refs:
            raise InsufficientEvidenceError(
                f"Finding {self.finding_id!r} ({self.title!r}) has no evidence or tool-result "
                "references. A finding must be traceable to real evidence — refusing to create "
                "an unsupported finding. Use explicit 'insufficient evidence' language in the "
                "investigation output instead of fabricating an unbacked finding."
            )

    def confirm(self, note: str | None = None) -> None:
        self.review_state = ReviewState.HUMAN_CONFIRMED
        self.analyst_note = note
        self.updated_at = time.time()

    def reject(self, note: str | None = None) -> None:
        self.review_state = ReviewState.HUMAN_REJECTED
        self.analyst_note = note
        self.updated_at = time.time()

    def flag_for_review(self, note: str | None = None) -> None:
        self.review_state = ReviewState.NEEDS_REVIEW
        self.analyst_note = note
        self.updated_at = time.time()

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "summary": self.summary,
            "reasoning": self.reasoning,
            "evidence_refs": self.evidence_refs,
            "tool_result_refs": self.tool_result_refs,
            "review_state": self.review_state.value,
            "analyst_note": self.analyst_note,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        obj = cls.__new__(cls)  # bypass __post_init__ re-validation on reload
        obj.finding_id = d["finding_id"]
        obj.title = d["title"]
        obj.severity = Severity(d["severity"])
        obj.confidence = d["confidence"]
        obj.summary = d["summary"]
        obj.reasoning = d["reasoning"]
        obj.evidence_refs = d.get("evidence_refs", [])
        obj.tool_result_refs = d.get("tool_result_refs", [])
        obj.review_state = ReviewState(d.get("review_state", "ai_proposed"))
        obj.analyst_note = d.get("analyst_note")
        obj.created_at = d.get("created_at", time.time())
        obj.updated_at = d.get("updated_at", time.time())
        return obj


class FindingStore:
    """Per-case findings, persisted to <case_workspace>/findings/findings.json."""

    def __init__(self, case_workspace: Path) -> None:
        self.case_workspace = Path(case_workspace)
        self.findings_dir = self.case_workspace / "findings"
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, Finding] = {}
        self._counter = itertools.count(1)
        self._load()

    def create(
        self,
        *,
        title: str,
        severity: Severity,
        confidence: float,
        summary: str,
        reasoning: str,
        evidence_refs: list[str] | None = None,
        tool_result_refs: list[str] | None = None,
    ) -> Finding:
        fid = f"F-{next(self._counter):04d}"
        finding = Finding(
            finding_id=fid,
            title=title,
            severity=severity,
            confidence=confidence,
            summary=summary,
            reasoning=reasoning,
            evidence_refs=evidence_refs or [],
            tool_result_refs=tool_result_refs or [],
        )  # raises InsufficientEvidenceError if unbacked -- propagates to caller
        self._items[fid] = finding
        self._save()
        return finding

    def get(self, finding_id: str) -> Finding | None:
        return self._items.get(finding_id)

    def all(self) -> list[Finding]:
        return list(self._items.values())

    def confirmed(self) -> list[Finding]:
        return [f for f in self._items.values() if f.review_state == ReviewState.HUMAN_CONFIRMED]

    def save(self) -> None:
        self._save()

    def _save(self) -> None:
        path = self.findings_dir / "findings.json"
        path.write_text(json.dumps([f.to_dict() for f in self._items.values()], indent=2))

    def _load(self) -> None:
        path = self.findings_dir / "findings.json"
        if not path.exists():
            return
        max_num = 0
        for d in json.loads(path.read_text()):
            finding = Finding.from_dict(d)
            self._items[finding.finding_id] = finding
            try:
                max_num = max(max_num, int(finding.finding_id.split("-")[1]))
            except (IndexError, ValueError):
                pass
        self._counter = itertools.count(max_num + 1)
