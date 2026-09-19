"""Challenge intake.

Every challenge gets an isolated workspace. Original inputs are preserved
untouched; all analysis artifacts go into subdirectories. Challenge content
(files, descriptions, hints, filenames) is ALWAYS untrusted data — never
treated as instructions to CYPHER or the underlying AI provider.
"""
from __future__ import annotations

import hashlib
import mimetypes
import shutil
import time
import uuid
import zipfile
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

MAX_ARCHIVE_EXTRACT_BYTES = 500 * 1024 * 1024  # 500MB decompression-bomb ceiling
MAX_ARCHIVE_MEMBER_COUNT = 5000


class UnsafeArchiveError(RuntimeError):
    pass


@dataclass
class ChallengeFile:
    original_name: str
    stored_path: Path
    size_bytes: int
    sha256: str
    mime_type: str

    def to_dict(self) -> dict:
        return {
            "original_name": self.original_name,
            "stored_path": str(self.stored_path),
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "mime_type": self.mime_type,
        }


@dataclass
class Challenge:
    challenge_id: str
    workspace: Path
    description: str = ""
    hints: list[str] = field(default_factory=list)
    files: list[ChallengeFile] = field(default_factory=list)
    source: str = "local"
    category_hint: str | None = None
    created_at: float = field(default_factory=time.time)
    authorized_urls: list[str] = field(default_factory=list)  # operator-supplied
    # web target(s). Web tools may ONLY fetch same-origin URLs relative to
    # these — see tools/web/fetcher.py. Empty means no web tools apply.

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "workspace": str(self.workspace),
            "description": self.description,
            "hints": self.hints,
            "files": [f.to_dict() for f in self.files],
            "source": self.source,
            "category_hint": self.category_hint,
            "created_at": self.created_at,
            "authorized_urls": self.authorized_urls,
        }


def _sanitize_filename(name: str) -> str:
    """Strip path components and traversal sequences from an untrusted name."""
    name = Path(name).name  # drops any directory components
    name = name.replace("..", "_")
    if not name or name in (".", ".."):
        name = "unnamed_file"
    return name


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_extract_zip(archive_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBER_COUNT:
            raise UnsafeArchiveError("Archive has too many members (possible zip bomb).")
        total = 0
        for info in infos:
            total += info.file_size
            if total > MAX_ARCHIVE_EXTRACT_BYTES:
                raise UnsafeArchiveError("Archive exceeds safe decompression size limit.")
            target = (dest / _sanitize_filename(info.filename)).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise UnsafeArchiveError(f"Path traversal attempt in archive member: {info.filename!r}")
        zf.extractall(dest, members=[i for i in infos])


def _safe_extract_tar(archive_path: Path, dest: Path) -> None:
    with tarfile.open(archive_path) as tf:
        members = tf.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBER_COUNT:
            raise UnsafeArchiveError("Archive has too many members (possible tar bomb).")
        total = 0
        for m in members:
            if m.issym() or m.islnk():
                raise UnsafeArchiveError(f"Refusing to extract symlink/hardlink member: {m.name!r}")
            total += m.size
            if total > MAX_ARCHIVE_EXTRACT_BYTES:
                raise UnsafeArchiveError("Archive exceeds safe decompression size limit.")
            target = (dest / _sanitize_filename(m.name)).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise UnsafeArchiveError(f"Path traversal attempt in archive member: {m.name!r}")
        tf.extractall(dest, members=members)


ARCHIVE_EXTRACTORS = {
    ".zip": _safe_extract_zip,
    ".tar": _safe_extract_tar,
    ".tgz": _safe_extract_tar,
    ".gz": _safe_extract_tar,
    ".tar.gz": _safe_extract_tar,
}


class ChallengeIntake:
    """Creates isolated workspaces and ingests challenge material into them."""

    def __init__(self, workspaces_root: Path) -> None:
        self.workspaces_root = workspaces_root
        self.workspaces_root.mkdir(parents=True, exist_ok=True)

    def new_workspace(self, challenge_id: str | None = None) -> Path:
        challenge_id = challenge_id or uuid.uuid4().hex[:12]
        ws = self.workspaces_root / challenge_id
        (ws / "originals").mkdir(parents=True, exist_ok=True)
        (ws / "extracted").mkdir(parents=True, exist_ok=True)
        (ws / "evidence").mkdir(parents=True, exist_ok=True)
        return ws

    def ingest_text(self, description: str, hints: list[str] | None = None) -> Challenge:
        ws = self.new_workspace()
        challenge = Challenge(
            challenge_id=ws.name,
            workspace=ws,
            description=description,
            hints=hints or [],
            source="text",
        )
        self._write_manifest(challenge)
        return challenge

    def ingest_url(self, url: str, description: str = "", hints: list[str] | None = None) -> Challenge:
        """A web challenge: no files, just one operator-authorized target
        URL. Web tools may only ever fetch same-origin URLs relative to
        this one — see tools/web/fetcher.py.
        """
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"Not a valid http(s) URL: {url!r}")

        ws = self.new_workspace()
        challenge = Challenge(
            challenge_id=ws.name,
            workspace=ws,
            description=description,
            hints=hints or [],
            source=url,
            category_hint="web",
            authorized_urls=[url],
        )
        self._write_manifest(challenge)
        return challenge

    def ingest_path(self, path: Path, description: str = "", hints: list[str] | None = None) -> Challenge:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Challenge path does not exist: {path}")

        ws = self.new_workspace()
        challenge = Challenge(
            challenge_id=ws.name,
            workspace=ws,
            description=description,
            hints=hints or [],
            source=str(path),
        )

        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    self._ingest_single_file(challenge, child)
        else:
            self._ingest_single_file(challenge, path)
            self._maybe_extract_archive(challenge, path)

        self._write_manifest(challenge)
        return challenge

    def _ingest_single_file(self, challenge: Challenge, src: Path) -> ChallengeFile:
        safe_name = _sanitize_filename(src.name)
        dest = challenge.workspace / "originals" / safe_name
        # avoid accidental overwrite of a same-named file
        counter = 1
        while dest.exists():
            dest = challenge.workspace / "originals" / f"{counter}_{safe_name}"
            counter += 1
        shutil.copy2(src, dest)
        mime, _ = mimetypes.guess_type(str(dest))
        cf = ChallengeFile(
            original_name=src.name,
            stored_path=dest,
            size_bytes=dest.stat().st_size,
            sha256=_sha256_of(dest),
            mime_type=mime or "application/octet-stream",
        )
        challenge.files.append(cf)
        return cf

    def _maybe_extract_archive(self, challenge: Challenge, src: Path) -> None:
        suffix = "".join(src.suffixes[-2:]) if src.name.endswith(".tar.gz") else src.suffix
        extractor = ARCHIVE_EXTRACTORS.get(suffix)
        if not extractor:
            return
        dest = challenge.workspace / "extracted"
        try:
            extractor(src, dest)
        except UnsafeArchiveError as exc:
            # Record but do not raise — an unsafe archive is evidence in itself,
            # not a reason to crash the intake pipeline.
            (challenge.workspace / "extracted" / "UNSAFE_ARCHIVE.txt").write_text(str(exc))
            return
        for child in sorted(dest.rglob("*")):
            if child.is_file():
                mime, _ = mimetypes.guess_type(str(child))
                challenge.files.append(
                    ChallengeFile(
                        original_name=str(child.relative_to(dest)),
                        stored_path=child,
                        size_bytes=child.stat().st_size,
                        sha256=_sha256_of(child),
                        mime_type=mime or "application/octet-stream",
                    )
                )

    def _write_manifest(self, challenge: Challenge) -> None:
        import json

        manifest_path = challenge.workspace / "manifest.json"
        manifest_path.write_text(json.dumps(challenge.to_dict(), indent=2))
