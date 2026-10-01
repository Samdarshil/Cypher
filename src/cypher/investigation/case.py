"""The Investigation (Case) model.

This is the top-level container Cypher 2.0 organizes everything around.
Deliberately built by adapting core/challenge.py's proven intake/hashing/
safe-extraction logic rather than rewriting it — that code was already
correct, just named for a different purpose (a CTF "challenge" is
structurally the same thing as an investigation "case": an isolated
workspace, a set of ingested files, metadata, timestamps).
"""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_CASE_ID_PATTERN = re.compile(r"^CASE-[0-9a-f]{8}$")


class InvalidCaseIdError(RuntimeError):
    pass


def _validate_case_id(case_id: str) -> str:
    """Every case_id this module ever uses to build a filesystem path
    must pass this check first. case_id is externally supplied (from
    the CLI/API, ultimately from whoever is driving Cypher), so a
    crafted value like '../../etc' must be rejected before it's ever
    joined onto cases_root -- otherwise CaseManager.get_case() can be
    made to escape the cases directory entirely (confirmed exploitable
    prior to this check: a case_id of '../some_other_dir' loaded an
    arbitrary directory's metadata.json as if it were a real case, and
    every subsequent EvidenceRegistry/FindingStore/etc. operation would
    then read/write outside cases_root).
    """
    if not _CASE_ID_PATTERN.match(case_id):
        raise InvalidCaseIdError(
            f"Invalid case ID: {case_id!r}. Expected format: CASE-xxxxxxxx (8 hex chars)."
        )
    return case_id


class InvestigationCaseStatus(str, Enum):
    OPEN = "open"
    ANALYZING = "analyzing"
    REVIEW = "review"           # findings exist, awaiting human confirm/reject
    CLOSED = "closed"


@dataclass
class InvestigationCase:
    case_id: str
    name: str
    description: str = ""
    status: InvestigationCaseStatus = InvestigationCaseStatus.OPEN
    workspace: Path = field(default=None)  # type: ignore[assignment]
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    evidence_ids: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)

    def touch(self) -> None:
        self.updated_at = time.time()

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "workspace": str(self.workspace),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence_ids": self.evidence_ids,
            "finding_ids": self.finding_ids,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "InvestigationCase":
        return cls(
            case_id=d["case_id"],
            name=d["name"],
            description=d.get("description", ""),
            status=InvestigationCaseStatus(d.get("status", "open")),
            workspace=Path(d["workspace"]),
            created_at=d.get("created_at", time.time()),
            updated_at=d.get("updated_at", time.time()),
            evidence_ids=d.get("evidence_ids", []),
            finding_ids=d.get("finding_ids", []),
        )


class CaseNotFoundError(RuntimeError):
    pass


class CaseManager:
    """Creates and persists cases. Each case is fully independent — its
    own workspace directory, its own metadata file — so cases never
    interfere with each other (spec section 4: "Cases must be
    independent.").
    """

    def __init__(self, cases_root: Path) -> None:
        self.cases_root = Path(cases_root)
        self.cases_root.mkdir(parents=True, exist_ok=True)

    def create_case(self, name: str, description: str = "") -> InvestigationCase:
        case_id = f"CASE-{uuid.uuid4().hex[:8]}"
        workspace = self.cases_root / case_id
        for sub in ("evidence", "results", "findings", "timeline"):
            (workspace / sub).mkdir(parents=True, exist_ok=True)
        case = InvestigationCase(case_id=case_id, name=name, description=description, workspace=workspace)
        self._save(case)
        return case

    def get_case(self, case_id: str) -> InvestigationCase:
        _validate_case_id(case_id)
        path = self.cases_root / case_id / "metadata.json"
        if not path.exists():
            raise CaseNotFoundError(f"No such case: {case_id!r}")
        return InvestigationCase.from_dict(json.loads(path.read_text()))

    def list_cases(self) -> list[InvestigationCase]:
        cases = []
        for entry in sorted(self.cases_root.iterdir()):
            meta = entry / "metadata.json"
            if meta.exists():
                cases.append(InvestigationCase.from_dict(json.loads(meta.read_text())))
        return cases

    def save(self, case: InvestigationCase) -> None:
        _validate_case_id(case.case_id)
        case.touch()
        self._save(case)

    def _save(self, case: InvestigationCase) -> None:
        path = case.workspace / "metadata.json"
        path.write_text(json.dumps(case.to_dict(), indent=2))
