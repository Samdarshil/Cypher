from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field


@dataclass
class Evidence:
    id: str
    source_tool: str
    input_ref: str
    summary: str
    raw_output_path: str
    relevance: float  # 0..1, how relevant to the current investigation
    supports: list[str] = field(default_factory=list)      # hypothesis IDs
    contradicts: list[str] = field(default_factory=list)   # hypothesis IDs
    timestamp: float = field(default_factory=time.time)
    interpretation: str | None = None  # AI's stated reasoning about this
    # evidence ("what did we learn"). Purely descriptive/for the human
    # report — NEVER a source for flag extraction. Flag candidates are
    # only ever pulled from raw_output_path (real tool output), never
    # from this field, so a model asserting "the flag is X" here can
    # never itself become a CONFIRMED result. See test_ai_resilience.py::
    # test_model_suggested_flag_in_interpretation_is_never_confirmed.

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_tool": self.source_tool,
            "input_ref": self.input_ref,
            "summary": self.summary,
            "raw_output_path": self.raw_output_path,
            "relevance": self.relevance,
            "supports": self.supports,
            "contradicts": self.contradicts,
            "timestamp": self.timestamp,
            "interpretation": self.interpretation,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        return cls(**d)


class EvidenceStore:
    """Append-only record of everything CYPHER has discovered.

    Backed by a directory of raw output files plus an in-memory index, so
    the investigation loop can always answer "why do you believe this?"
    by walking evidence -> hypothesis links.
    """

    def __init__(self, evidence_dir) -> None:
        from pathlib import Path

        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, Evidence] = {}
        self._id_counter = itertools.count(1)

    def add(
        self,
        *,
        source_tool: str,
        input_ref: str,
        summary: str,
        raw_output: str,
        relevance: float,
        supports: list[str] | None = None,
        contradicts: list[str] | None = None,
        interpretation: str | None = None,
    ) -> Evidence:
        eid = f"E{next(self._id_counter)}"
        raw_path = self.evidence_dir / f"{eid}.txt"
        raw_path.write_text(raw_output)
        ev = Evidence(
            id=eid,
            source_tool=source_tool,
            input_ref=input_ref,
            summary=summary,
            raw_output_path=str(raw_path),
            relevance=relevance,
            supports=supports or [],
            contradicts=contradicts or [],
            interpretation=interpretation,
        )
        self._items[eid] = ev
        return ev

    def set_interpretation(self, eid: str, text: str) -> None:
        if eid in self._items:
            self._items[eid].interpretation = text

    def get(self, eid: str) -> Evidence | None:
        return self._items.get(eid)

    def all(self) -> list[Evidence]:
        return list(self._items.values())

    def raw_text(self, eid: str) -> str:
        ev = self._items[eid]
        from pathlib import Path

        return Path(ev.raw_output_path).read_text(errors="replace")

    def search_raw(self, needle: str) -> list[Evidence]:
        """Which evidence entries literally contain this substring in their
        raw tool output? Used by the flag verifier — a flag must actually
        appear in real tool output, not just be asserted by the LLM.
        """
        hits = []
        for ev in self._items.values():
            try:
                if needle in self.raw_text(ev.id):
                    hits.append(ev)
            except FileNotFoundError:
                continue
        return hits

    def to_list(self) -> list[dict]:
        return [e.to_dict() for e in self._items.values()]

    @classmethod
    def from_list(cls, evidence_dir, items: list[dict]) -> "EvidenceStore":
        store = cls(evidence_dir)
        max_num = 0
        for item in items:
            ev = Evidence.from_dict(item)
            store._items[ev.id] = ev
            try:
                max_num = max(max_num, int(ev.id.lstrip("E")))
            except ValueError:
                pass
        store._id_counter = itertools.count(max_num + 1)
        return store
