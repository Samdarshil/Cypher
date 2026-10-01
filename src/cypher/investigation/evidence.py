"""Evidence item model.

Reuses the hashing/MIME-detection/safe-copy logic already proven correct
in core/challenge.py (sha256, mimetypes, path sanitization) rather than
reimplementing it — only the identifier scheme and metadata shape are new
(EVID-XXXX, analysis_state, source), matching spec section 7.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import mimetypes
import os
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from cypher.core.challenge import _sanitize_filename  # reuse, don't duplicate


class AnalysisState(str, Enum):
    REGISTERED = "registered"     # ingested, not yet analyzed
    ANALYZING = "analyzing"       # a tool is currently running against it
    ANALYZED = "analyzed"         # at least one tool has produced a result
    ERROR = "error"


@dataclass
class EvidenceItem:
    evidence_id: str          # "EVID-0001"
    original_name: str
    stored_path: Path
    size_bytes: int
    sha256: str
    mime_type: str
    source: str                # e.g. "upload", "extracted-from:EVID-0001"
    ingested_at: float = field(default_factory=time.time)
    analysis_state: AnalysisState = AnalysisState.REGISTERED
    result_refs: list[str] = field(default_factory=list)  # tool result IDs

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "original_name": self.original_name,
            "stored_path": str(self.stored_path),
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "mime_type": self.mime_type,
            "source": self.source,
            "ingested_at": self.ingested_at,
            "analysis_state": self.analysis_state.value,
            "result_refs": self.result_refs,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceItem":
        return cls(
            evidence_id=d["evidence_id"],
            original_name=d["original_name"],
            stored_path=Path(d["stored_path"]),
            size_bytes=d["size_bytes"],
            sha256=d["sha256"],
            mime_type=d["mime_type"],
            source=d.get("source", "upload"),
            ingested_at=d.get("ingested_at", time.time()),
            analysis_state=AnalysisState(d.get("analysis_state", "registered")),
            result_refs=d.get("result_refs", []),
        )


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class EvidenceRegistry:
    """Per-case evidence inventory. Assigns stable EVID-XXXX identifiers
    and persists metadata to <case_workspace>/evidence/inventory.json.
    """

    def __init__(self, case_workspace: Path) -> None:
        self.case_workspace = Path(case_workspace)
        self.evidence_dir = self.case_workspace / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, EvidenceItem] = {}
        self._counter = itertools.count(1)
        self._lock = threading.RLock()
        self._load()

    def register_file(self, src: Path, source: str = "upload", original_name: str | None = None) -> EvidenceItem:
        with self._lock:
            return self._register_file(src, source, original_name)

    def _register_file(self, src: Path, source: str, original_name: str | None) -> EvidenceItem:
        """Copy a file into the case's evidence directory and register it
        with a stable ID. Filename collisions and traversal are handled
        the same way core/challenge.py's intake already does.
        """
        src = Path(src)
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(f"Evidence source does not exist or is not a file: {src}")

        eid = f"EVID-{next(self._counter):04d}"
        display_name = original_name or src.name
        safe_name = _sanitize_filename(display_name)[:255] or "unnamed_file"
        dest = self.evidence_dir / f"{eid}_{safe_name}"
        try:
            shutil.copy2(src, dest)
            mime, _ = mimetypes.guess_type(display_name)
            item = EvidenceItem(
                evidence_id=eid,
                original_name=display_name,
                stored_path=dest,
                size_bytes=dest.stat().st_size,
                sha256=_sha256_of(dest),
                mime_type=mime or "application/octet-stream",
                source=source,
            )
            self._items[eid] = item
            self._save()
            return item
        except Exception:
            self._items.pop(eid, None)
            dest.unlink(missing_ok=True)
            raise

    def get(self, evidence_id: str) -> EvidenceItem | None:
        return self._items.get(evidence_id)

    def all(self) -> list[EvidenceItem]:
        return list(self._items.values())

    def mark_state(self, evidence_id: str, state: AnalysisState) -> None:
        item = self._items.get(evidence_id)
        if item:
            item.analysis_state = state
            self._save()

    def attach_result(self, evidence_id: str, result_id: str) -> None:
        item = self._items.get(evidence_id)
        if item and result_id not in item.result_refs:
            item.result_refs.append(result_id)
            item.analysis_state = AnalysisState.ANALYZED
            self._save()

    def _save(self) -> None:
        path = self.evidence_dir / "inventory.json"
        payload = json.dumps([i.to_dict() for i in self._items.values()], indent=2)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.evidence_dir, prefix="inventory-", suffix=".tmp", delete=False) as fh:
                temp_path = Path(fh.name)
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_path, path)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def _load(self) -> None:
        path = self.evidence_dir / "inventory.json"
        if not path.exists():
            return
        max_num = 0
        for d in json.loads(path.read_text()):
            item = EvidenceItem.from_dict(d)
            self._items[item.evidence_id] = item
            try:
                max_num = max(max_num, int(item.evidence_id.split("-")[1]))
            except (IndexError, ValueError):
                pass
        self._counter = itertools.count(max_num + 1)
