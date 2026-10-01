"""Observations (spec §7).

An Observation is a normalized fact extracted from a real ToolResult —
never invented. Extraction reuses the exact same regex patterns already
proven in tools/osint/scripts/entity_extract.py (emails, domains, IPs,
handles, dates, hex blobs) rather than duplicating that logic, applied
here to ANY tool result, not just the OSINT tool specifically.
"""
from __future__ import annotations

import itertools
import json
import re
from dataclasses import dataclass
from pathlib import Path

_PATTERNS = [
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("url", re.compile(r"https?://[^\s\"'<>]+")),
    ("domain", re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|dev|co|info|xyz|edu|gov)\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("sha256", re.compile(r"\b[0-9a-fA-F]{64}\b")),
    ("md5_or_sha1", re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b")),
]


@dataclass
class Observation:
    observation_id: str          # "OBS-0001"
    type: str                    # "email" | "url" | "domain" | "ipv4" | "sha256" | ...
    value: str
    source_result_id: str        # id into the AnalysisOrchestrator's EvidenceStore (raw results)
    evidence_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "observation_id": self.observation_id,
            "type": self.type,
            "value": self.value,
            "source_result_id": self.source_result_id,
            "evidence_id": self.evidence_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Observation":
        return cls(**d)


def extract_observations_from_text(text: str) -> list[tuple[str, str]]:
    """Pure function: (type, value) pairs literally present in `text`.
    No network, no inference beyond pattern matching — every result is
    traceable to an exact substring of the input.
    """
    found: list[tuple[str, str]] = []
    seen = set()
    for label, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            key = (label, match.group(0))
            if key in seen:
                continue
            seen.add(key)
            found.append(key)
    return found


class ObservationStore:
    def __init__(self, case_workspace: Path) -> None:
        self.case_workspace = Path(case_workspace)
        self.dir = self.case_workspace / "observations"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, Observation] = {}
        self._counter = itertools.count(1)
        self._load()

    def extract_from_result(self, raw_text: str, source_result_id: str, evidence_id: str | None = None) -> list[Observation]:
        created = []
        for otype, value in extract_observations_from_text(raw_text):
            oid = f"OBS-{next(self._counter):04d}"
            obs = Observation(observation_id=oid, type=otype, value=value,
                               source_result_id=source_result_id, evidence_id=evidence_id)
            self._items[oid] = obs
            created.append(obs)
        if created:
            self._save()
        return created

    def get(self, observation_id: str) -> Observation | None:
        return self._items.get(observation_id)

    def all(self) -> list[Observation]:
        return list(self._items.values())

    def exists_all(self, ids: list[str]) -> bool:
        return all(i in self._items for i in ids)

    def _save(self) -> None:
        (self.dir / "observations.json").write_text(
            json.dumps([o.to_dict() for o in self._items.values()], indent=2)
        )

    def _load(self) -> None:
        path = self.dir / "observations.json"
        if not path.exists():
            return
        max_num = 0
        for d in json.loads(path.read_text()):
            obs = Observation.from_dict(d)
            self._items[obs.observation_id] = obs
            try:
                max_num = max(max_num, int(obs.observation_id.split("-")[1]))
            except (IndexError, ValueError):
                pass
        self._counter = itertools.count(max_num + 1)
