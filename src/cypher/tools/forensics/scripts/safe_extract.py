#!/usr/bin/env python3
"""Safe archive extractor for mid-investigation use (e.g. binwalk finds a
payload.zip inside a PNG; CYPHER needs to extract it to keep investigating).

Reuses the same protections as challenge intake: path-traversal checks,
a decompression-bomb size ceiling, a member-count ceiling, and symlink
refusal for tar archives. Stdlib only, no subprocess spawned (consistent
with "the executor is the only place a subprocess is spawned" — this
script is a fixed, non-LLM-controlled tool, not an arbitrary command).
"""
from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

MAX_EXTRACT_BYTES = 200 * 1024 * 1024
MAX_MEMBERS = 2000


def _safe_name(name: str) -> str:
    name = Path(name).name
    name = name.replace("..", "_")
    return name or "unnamed"


def extract_zip(archive: Path, dest: Path) -> list[str]:
    extracted = []
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            print(f"REFUSED: too many members ({len(infos)}) — possible zip bomb", file=sys.stderr)
            return []
        total = 0
        for info in infos:
            total += info.file_size
            if total > MAX_EXTRACT_BYTES:
                print("REFUSED: decompressed size exceeds safety limit", file=sys.stderr)
                return []
            target = (dest / _safe_name(info.filename)).resolve()
            if not str(target).startswith(str(dest.resolve())):
                print(f"REFUSED: path traversal in member {info.filename!r}", file=sys.stderr)
                return []
        for info in infos:
            safe_name = _safe_name(info.filename)
            if not safe_name or info.is_dir():
                continue
            data = zf.read(info)
            out_path = dest / safe_name
            out_path.write_bytes(data)
            extracted.append(safe_name)
    return extracted


def extract_tar(archive: Path, dest: Path) -> list[str]:
    extracted = []
    with tarfile.open(archive) as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            print(f"REFUSED: too many members ({len(members)}) — possible tar bomb", file=sys.stderr)
            return []
        total = 0
        for m in members:
            if m.issym() or m.islnk():
                print(f"REFUSED: symlink/hardlink member {m.name!r}", file=sys.stderr)
                return []
            total += m.size
            if total > MAX_EXTRACT_BYTES:
                print("REFUSED: decompressed size exceeds safety limit", file=sys.stderr)
                return []
            target = (dest / _safe_name(m.name)).resolve()
            if not str(target).startswith(str(dest.resolve())):
                print(f"REFUSED: path traversal in member {m.name!r}", file=sys.stderr)
                return []
        for m in members:
            if not m.isfile():
                continue
            safe_name = _safe_name(m.name)
            fh = tf.extractfile(m)
            if fh is None:
                continue
            (dest / safe_name).write_bytes(fh.read())
            extracted.append(safe_name)
    return extracted


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: safe_extract.py <archive>", file=sys.stderr)
        return 2
    archive = Path(sys.argv[1])
    dest = Path.cwd() / f"extracted_{archive.stem}"
    dest.mkdir(exist_ok=True)

    try:
        if zipfile.is_zipfile(archive):
            names = extract_zip(archive, dest)
        elif tarfile.is_tarfile(archive):
            names = extract_tar(archive, dest)
        else:
            print("Not a recognized zip/tar archive.", file=sys.stderr)
            return 1
    except Exception as exc:  # noqa: BLE001 -- surface any parse error as tool output, don't crash
        print(f"Extraction failed: {exc}", file=sys.stderr)
        return 1

    if not names:
        print("No files extracted (empty archive or refused for safety).")
        return 0
    for n in names:
        print(f"extracted: {dest.name}/{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
