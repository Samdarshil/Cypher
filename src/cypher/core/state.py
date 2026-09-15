from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from cypher.core.hypotheses import HypothesisBoard
from cypher.evidence.models import EvidenceStore


class InvestigationStatus(str, Enum):
    IN_PROGRESS = "IN_PROGRESS"
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    UNCONFIRMED = "UNCONFIRMED"
    NOT_YET_FOUND = "NOT_YET_FOUND"
    EXHAUSTED = "EXHAUSTED"


@dataclass
class ActionLogEntry:
    hypothesis_id: str | None
    tool_name: str
    args: list[str]
    reason: str
    success: bool
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id,
            "tool_name": self.tool_name,
            "args": self.args,
            "reason": self.reason,
            "success": self.success,
            "timestamp": self.timestamp,
        }


@dataclass
class DiscoveredArtifact:
    """A new file that appeared in the workspace as the output of a tool
    (e.g. binwalk_extract carving out payload.zip). Tracked so the
    investigation loop can recurse into it, with cycle/explosion
    prevention via sha256 identity and a depth ceiling.
    """
    name: str                 # basename, shown to the AI as a selectable "input"
    relative_path: str        # path relative to the challenge workspace root
    sha256: str
    produced_by_tool: str
    produced_by_evidence_id: str
    depth: int                # 0 = original challenge file; N = N tools deep

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "produced_by_tool": self.produced_by_tool,
            "produced_by_evidence_id": self.produced_by_evidence_id,
            "depth": self.depth,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DiscoveredArtifact":
        return cls(**d)


class InvestigationState:
    """Per-challenge state, persisted to <workspace>/state.json so an
    investigation can be resumed rather than restarted from scratch.
    """

    def __init__(self, challenge_id: str, workspace: Path) -> None:
        self.challenge_id = challenge_id
        self.workspace = Path(workspace)
        self.hypotheses = HypothesisBoard()
        self.evidence = EvidenceStore(self.workspace / "evidence")
        self.action_log: list[ActionLogEntry] = []
        self.failed_strategies: set[str] = set()  # "{tool}:{args}" fingerprints
        self.candidate_flags: list[dict] = []
        self.confirmed_flag: dict | None = None
        self.escalation_level: int = 1
        self.status: InvestigationStatus = InvestigationStatus.IN_PROGRESS
        self.created_at: float = time.time()
        self.updated_at: float = time.time()
        self.discovered_artifacts: list[DiscoveredArtifact] = []
        self.known_hashes: set[str] = set()  # every artifact/original hash ever seen (cycle guard)

    def strategy_fingerprint(self, tool_name: str, args: list[str]) -> str:
        return f"{tool_name}:{'|'.join(args)}"

    def already_tried(self, tool_name: str, args: list[str]) -> bool:
        return self.strategy_fingerprint(tool_name, args) in self.failed_strategies

    def mark_tried(self, tool_name: str, args: list[str]) -> None:
        self.failed_strategies.add(self.strategy_fingerprint(tool_name, args))

    def log_action(self, entry: ActionLogEntry) -> None:
        self.action_log.append(entry)
        self.updated_at = time.time()

    def escalate(self) -> None:
        self.escalation_level = min(8, self.escalation_level + 1)

    def register_artifact_if_new(self, artifact: DiscoveredArtifact) -> bool:
        """Returns True if this was actually new (and records it);
        False if its content hash was already seen (cycle prevented)."""
        if artifact.sha256 in self.known_hashes:
            return False
        self.known_hashes.add(artifact.sha256)
        self.discovered_artifacts.append(artifact)
        return True

    def save(self) -> Path:
        path = self.workspace / "state.json"
        payload = {
            "challenge_id": self.challenge_id,
            "hypotheses": self.hypotheses.to_list(),
            "evidence": self.evidence.to_list(),
            "action_log": [a.to_dict() for a in self.action_log],
            "failed_strategies": sorted(self.failed_strategies),
            "candidate_flags": self.candidate_flags,
            "confirmed_flag": self.confirmed_flag,
            "escalation_level": self.escalation_level,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "discovered_artifacts": [a.to_dict() for a in self.discovered_artifacts],
            "known_hashes": sorted(self.known_hashes),
        }
        path.write_text(json.dumps(payload, indent=2))
        return path

    @classmethod
    def load_or_create(cls, challenge_id: str, workspace: Path) -> "InvestigationState":
        path = Path(workspace) / "state.json"
        state = cls(challenge_id, workspace)
        if path.exists():
            payload = json.loads(path.read_text())
            state.hypotheses = HypothesisBoard.from_list(payload.get("hypotheses", []))
            state.evidence = EvidenceStore.from_list(
                Path(workspace) / "evidence", payload.get("evidence", [])
            )
            state.failed_strategies = set(payload.get("failed_strategies", []))
            state.candidate_flags = payload.get("candidate_flags", [])
            state.confirmed_flag = payload.get("confirmed_flag")
            state.escalation_level = payload.get("escalation_level", 1)
            state.status = InvestigationStatus(payload.get("status", "IN_PROGRESS"))
            state.created_at = payload.get("created_at", time.time())
            state.discovered_artifacts = [
                DiscoveredArtifact.from_dict(d) for d in payload.get("discovered_artifacts", [])
            ]
            state.known_hashes = set(payload.get("known_hashes", []))
        return state
