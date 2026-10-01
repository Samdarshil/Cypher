#!/usr/bin/env python3
"""Fixed, deterministic multi-encoding auto-decoder.

This is registered as a CYPHER tool (see tools/crypto/specs.py) rather than
called ad hoc: the LLM can only invoke it by name through the registry, it
cannot alter its contents or arguments beyond the input file, and it spawns
no subprocesses itself (stdlib only) — consistent with "the executor is the
only place a subprocess is spawned."

Tries, in order: base64 (standard + urlsafe), hex, binary (0/1 groups),
Caesar/ROT-N (all 25 shifts), and single-byte XOR against a small set of
likely keys (0x00-0xFF) filtering for printable output. Prints every
plausible decode as a labeled candidate line so the flag-format regex
extractor can pick up a flag if one appears in any of them.

Read-only: takes exactly one argument, the input file path, and only reads
it. Never writes outside CWD (writes nothing at all, in fact).
"""
from __future__ import annotations

import base64
import re
import string
import sys

PRINTABLE = set(string.printable)


def _looks_mostly_printable(data: bytes, threshold: float = 0.85) -> bool:
    if not data:
        return False
    printable_count = sum(1 for b in data if chr(b) in PRINTABLE)
    return (printable_count / len(data)) >= threshold


def try_base64(raw: bytes) -> list[str]:
    out = []
    text = raw.decode("ascii", errors="ignore").strip()
    for variant, decoder in (("base64", base64.b64decode), ("base64-urlsafe", base64.urlsafe_b64decode)):
        candidate = re.sub(r"\s+", "", text)
        if not candidate or not re.fullmatch(r"[A-Za-z0-9+/_=\-]+", candidate):
            continue
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = decoder(padded)
        except Exception:
            continue
        if _looks_mostly_printable(decoded):
            out.append(f"[{variant}] {decoded.decode('utf-8', errors='replace')}")
    return out


def try_hex(raw: bytes) -> list[str]:
    text = re.sub(r"[^0-9a-fA-F]", "", raw.decode("ascii", errors="ignore"))
    if len(text) < 4 or len(text) % 2 != 0:
        return []
    try:
        decoded = bytes.fromhex(text)
    except ValueError:
        return []
    if _looks_mostly_printable(decoded):
        return [f"[hex] {decoded.decode('utf-8', errors='replace')}"]
    return []


def try_binary(raw: bytes) -> list[str]:
    text = raw.decode("ascii", errors="ignore")
    bits = re.sub(r"[^01]", "", text)
    if len(bits) < 8 or len(bits) % 8 != 0:
        return []
    try:
        decoded = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))
    except ValueError:
        return []
    if _looks_mostly_printable(decoded):
        return [f"[binary] {decoded.decode('utf-8', errors='replace')}"]
    return []


_COMMON_WORDS = {
    "the", "flag", "and", "you", "this", "are", "for", "with", "that", "have",
    "ctf", "here", "your", "was", "not", "but", "can", "all", "has", "one",
    "hidden", "secret", "message", "found", "welcome", "congrat", "well", "done",
}


def try_rot_n(raw: bytes) -> list[str]:
    """Only ROT13 is common in real CTFs, but we score all 25 shifts and
    surface only the single best-scoring one (by common-English-word count),
    since '{' and '}' pass through unshifted — meaning a naive "contains a
    flag-shaped substring" check would spuriously match EVERY rotation and
    risk confirming the wrong one. Scoring by real-word content instead
    means only the actually-correct rotation should win.
    """
    text = raw.decode("utf-8", errors="ignore")
    if not text.strip():
        return []

    scored: list[tuple[int, int, str]] = []  # (score, shift, candidate)
    for shift in range(1, 26):
        decoded_chars = []
        for ch in text:
            if ch.isupper():
                decoded_chars.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            elif ch.islower():
                decoded_chars.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            else:
                decoded_chars.append(ch)
        candidate = "".join(decoded_chars)
        words = re.findall(r"[a-z]+", candidate.lower())
        score = sum(1 for w in words if w in _COMMON_WORDS)
        if score > 0:
            scored.append((score, shift, candidate))

    if not scored:
        return []

    scored.sort(reverse=True)
    top_score = scored[0][0]
    winners = [s for s in scored if s[0] == top_score]
    if len(winners) > 1:
        # Ambiguous — don't guess, report the top candidates so a human/LLM
        # can pick, but don't let any single one look uniquely confirmed.
        return [f"[rot{shift}-ambiguous] {cand}" for _, shift, cand in winners[:3]]
    _, shift, cand = winners[0]
    return [f"[rot{shift}] {cand}"]


def try_single_byte_xor(raw: bytes) -> list[str]:
    if len(raw) > 20000:  # keep this fast; large files aren't typical XOR-single-byte targets
        raw = raw[:20000]
    out = []
    for key in range(1, 256):  # skip 0x00 (identity — not actually a decode)
        decoded = bytes(b ^ key for b in raw)
        if _looks_mostly_printable(decoded, threshold=0.95):
            try:
                text = decoded.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if re.search(r"[A-Za-z0-9_]{3,20}\{[^{}\s]{1,80}\}", text):
                out.append(f"[xor-0x{key:02x}] {text}")
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: auto_decode.py <file>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as fh:
        raw = fh.read()

    results: list[str] = []
    results += try_base64(raw)
    results += try_hex(raw)
    results += try_binary(raw)
    results += try_rot_n(raw)
    results += try_single_byte_xor(raw)

    if not results:
        print("No plausible decodings found across base64/hex/binary/rot-n/single-byte-xor.")
        return 0

    for line in results:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
