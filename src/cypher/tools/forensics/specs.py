"""Forensics tool declarations. Registered into the default registry;
each one no-ops via is_available() if the binary isn't installed, so
CYPHER degrades gracefully instead of crashing on an incomplete machine.
"""
from __future__ import annotations

from pathlib import Path

from cypher.tools.schemas import SafetyClass, ToolSpec

_SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"
_SAFE_EXTRACT_SCRIPT = str(_SCRIPT_DIR / "safe_extract.py")


def forensics_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="safe_archive_extract",
            category="forensics",
            description=(
                "Safely extract a zip/tar archive (path-traversal-proof, "
                "decompression-bomb-limited) into a new subdirectory, printing "
                "the names of files it extracted. Use this on any file identified "
                "as an archive, including one discovered inside another file."
            ),
            executable="python3",
            arg_template=[_SAFE_EXTRACT_SCRIPT, "{input}"],
            input_types=["archive"],
            timeout_seconds=30,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="exif_metadata",
            category="forensics",
            description=(
                "Dump all embedded metadata (EXIF, XMP, IPTC, camera/software info, "
                "GPS coordinates if present, hidden comment fields). Best first step "
                "for any image/media/document challenge file."
            ),
            executable="exiftool",
            arg_template=["-a", "-u", "-g1", "{input}"],
            input_types=["image", "audio", "video", "pdf", "any"],
            timeout_seconds=20,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="binwalk_scan",
            category="forensics",
            description=(
                "Scan a file for embedded/appended files, filesystems, and known "
                "magic-byte signatures (e.g. a ZIP or PNG hidden inside another file). "
                "Does NOT extract by default — read-only signature scan."
            ),
            executable="binwalk",
            arg_template=["{input}"],
            input_types=["any"],
            timeout_seconds=30,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
        ToolSpec(
            name="binwalk_extract",
            category="forensics",
            description=(
                "Like binwalk_scan but also carves out any embedded files it finds "
                "into an extraction directory. Use only after binwalk_scan shows a hit "
                "worth pulling out."
            ),
            executable="binwalk",
            arg_template=["-e", "--dd=.*", "{input}"],
            input_types=["any"],
            timeout_seconds=60,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
        ToolSpec(
            name="foremost_carve",
            category="forensics",
            description="Carve known file types out of a raw blob/disk image by signature.",
            executable="foremost",
            arg_template=["-i", "{input}", "-o", "carved_output"],
            input_types=["binary", "disk_image"],
            timeout_seconds=60,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
    ]
