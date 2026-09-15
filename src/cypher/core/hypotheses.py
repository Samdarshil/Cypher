"""Multi-hypothesis reasoning support.

Hypotheses are never permanent truth. Priority moves up and down as
evidence accumulates; failed approaches reduce priority instead of being
deleted, so the system doesn't retry them but can still show its work,
and so the loop doesn't tunnel forever into a single dead-end hypothesis.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import Enum

# "Pursuable" statuses -- the ones top()/active() will still select from.
PURSUABLE = {"active", "supported", "weakened"}


class HypothesisStatus(str, Enum):
    ACTIVE = "active"
    SUPPORTED = "supported"    # meaningfully backed by evidence
    WEAKENED = "weakened"      # still pursuable, but losing confidence
    REJECTED = "rejected"      # abandoned — will not be retried
    CONFIRMED = "confirmed"    # led to the confirmed flag
    EXHAUSTED = "exhausted"    # every relevant tool for this hypothesis has been tried


@dataclass
class Hypothesis:
    id: str
    statement: str
    category: str
    priority: float = 0.5  # 0..1, mutable
    status: HypothesisStatus = HypothesisStatus.ACTIVE
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    attempted_actions: list[str] = field(default_factory=list)   # "tool:input" fingerprints
    successful_actions: list[str] = field(default_factory=list)  # produced evidence/candidates
    failed_actions: list[str] = field(default_factory=list)
    failure_count: int = 0

    def record_attempt(self, fingerprint: str, succeeded: bool) -> None:
        self.attempted_actions.append(fingerprint)
        (self.successful_actions if succeeded else self.failed_actions).append(fingerprint)

    def record_support(self, evidence_id: str, boost: float = 0.15) -> None:
        self.supporting_evidence.append(evidence_id)
        self.priority = min(1.0, self.priority + boost)
        if self.status in (HypothesisStatus.ACTIVE, HypothesisStatus.WEAKENED) and self.priority > 0.6:
            self.status = HypothesisStatus.SUPPORTED

    def record_contradiction(self, evidence_id: str, penalty: float = 0.2) -> None:
        self.contradicting_evidence.append(evidence_id)
        self.priority = max(0.0, self.priority - penalty)
        if self.priority < 0.3 and self.status not in (HypothesisStatus.REJECTED, HypothesisStatus.CONFIRMED):
            self.status = HypothesisStatus.WEAKENED

    def record_failure(self, penalty: float = 0.25) -> None:
        self.failure_count += 1
        self.priority = max(0.0, self.priority - penalty)
        if self.failure_count >= 3 and self.priority < 0.15:
            self.status = HypothesisStatus.REJECTED
        elif self.failure_count >= 2 and self.status == HypothesisStatus.ACTIVE:
            self.status = HypothesisStatus.WEAKENED

    def mark_exhausted(self) -> None:
        """Called by the investigation loop when every registered tool
        applicable to this hypothesis has already been tried on every
        available input — distinct from REJECTED (which means the
        evidence actively argues against it).
        """
        if self.status not in (HypothesisStatus.REJECTED, HypothesisStatus.CONFIRMED):
            self.status = HypothesisStatus.EXHAUSTED

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "statement": self.statement,
            "category": self.category,
            "priority": self.priority,
            "status": self.status.value,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "attempted_actions": self.attempted_actions,
            "successful_actions": self.successful_actions,
            "failed_actions": self.failed_actions,
            "failure_count": self.failure_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Hypothesis":
        return cls(
            id=d["id"],
            statement=d["statement"],
            category=d["category"],
            priority=d.get("priority", 0.5),
            status=HypothesisStatus(d.get("status", "active")),
            supporting_evidence=d.get("supporting_evidence", []),
            contradicting_evidence=d.get("contradicting_evidence", []),
            attempted_actions=d.get("attempted_actions", []),
            successful_actions=d.get("successful_actions", []),
            failed_actions=d.get("failed_actions", []),
            failure_count=d.get("failure_count", 0),
        )


class HypothesisBoard:
    """Holds all hypotheses for one investigation and ranks them."""

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}
        self._id_counter = itertools.count(1)

    def add(self, statement: str, category: str, priority: float = 0.5) -> Hypothesis:
        hyp_id = f"H{next(self._id_counter)}"
        hyp = Hypothesis(id=hyp_id, statement=statement, category=category, priority=priority)
        self._hypotheses[hyp_id] = hyp
        return hyp

    def get(self, hyp_id: str) -> Hypothesis | None:
        return self._hypotheses.get(hyp_id)

    def active(self) -> list[Hypothesis]:
        """Still-pursuable hypotheses (active/supported/weakened), ranked."""
        return sorted(
            (h for h in self._hypotheses.values() if h.status.value in PURSUABLE),
            key=lambda h: h.priority,
            reverse=True,
        )

    def all(self) -> list[Hypothesis]:
        return list(self._hypotheses.values())

    def top(self) -> Hypothesis | None:
        active = self.active()
        return active[0] if active else None

    def to_list(self) -> list[dict]:
        return [h.to_dict() for h in self._hypotheses.values()]

    @classmethod
    def from_list(cls, items: list[dict]) -> "HypothesisBoard":
        board = cls()
        max_num = 0
        for item in items:
            hyp = Hypothesis.from_dict(item)
            board._hypotheses[hyp.id] = hyp
            try:
                num = int(hyp.id.lstrip("H"))
                max_num = max(max_num, num)
            except ValueError:
                pass
        board._id_counter = itertools.count(max_num + 1)
        return board
