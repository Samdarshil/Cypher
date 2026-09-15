#!/usr/bin/env python3
"""Deterministic entity extraction for OSINT-category challenges.

Pulls candidate entities (emails, domains, IPv4 addresses, @handles,
dates, hex-looking tokens) out of text using regex only — no network
access, no LLM call, nothing that could hallucinate a fact. Every line
this prints is literally present in the input; it is evidence, not a
conclusion. Real cross-source correlation (searching those entities
against public records) is NOT implemented here — that needs a search
tool this build doesn't have wired in, and is called out as a known
limitation rather than faked.
"""
from __future__ import annotations

import re
import sys

PATTERNS = [
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("url", re.compile(r"https?://[^\s\"'<>]+")),
    ("domain", re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|dev|co|info|xyz|edu|gov)\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("handle", re.compile(r"(?<!\w)@[A-Za-z0-9_]{2,30}\b")),
    ("date_iso", re.compile(r"\b\d{4}-\d{2}-\d{2}\b")),
    ("hex_blob", re.compile(r"\b[0-9a-fA-F]{16,}\b")),
]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: entity_extract.py <file>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "r", errors="replace") as fh:
        text = fh.read()

    seen = set()
    found_any = False
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            key = (label, value)
            if key in seen:
                continue
            seen.add(key)
            print(f"[{label}] {value}")
            found_any = True

    if not found_any:
        print("No OSINT-relevant entities (emails/URLs/domains/IPs/handles/dates/hex blobs) found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
