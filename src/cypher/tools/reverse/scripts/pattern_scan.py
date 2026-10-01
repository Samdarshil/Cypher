#!/usr/bin/env python3
"""Heuristic pattern scanner for reverse-engineering triage.

Honest scope: this is a printable-strings + regex scan, NOT real
disassembly or control-flow analysis. It flags the same surface patterns
an experienced CTF player scans for by eye when first opening a binary:
comparison-function names, XOR-loop-adjacent constants, base64/hex
alphabets, and hardcoded-secret-shaped strings. It tells you WHERE to
look with objdump/gdb next, not WHAT the binary does.
"""
from __future__ import annotations

import re
import sys

MIN_STRING_LEN = 4

SUSPICIOUS_SYMBOLS = {
    "strcmp", "strncmp", "memcmp", "strcasecmp", "strncasecmp",
    "crypt", "md5", "sha1", "sha256", "base64", "XOR", "xor",
    "password", "passwd", "secret", "flag", "key", "token",
    "atoi", "system", "exec", "popen", "gets", "sprintf", "strcpy",
}

BASE64_ALPHABET = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{16,}\b")
FLAG_SHAPE = re.compile(r"[A-Za-z0-9_]{3,20}\{[^{}\s]{1,200}\}")


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> list[str]:
    strings = []
    current = []
    for byte in data:
        ch = chr(byte)
        if 32 <= byte < 127:
            current.append(ch)
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: pattern_scan.py <binary>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()

    strings = extract_strings(data)
    findings = []

    for s in strings:
        low = s.lower()
        for sym in SUSPICIOUS_SYMBOLS:
            if sym in low:
                findings.append(f"[suspicious_symbol:{sym}] {s}")
                break
        if FLAG_SHAPE.search(s):
            findings.append(f"[flag_shape] {s}")
        if BASE64_ALPHABET.fullmatch(s) and len(set(s)) > 10:
            findings.append(f"[base64_like] {s}")
        if HEX_BLOB.fullmatch(s):
            findings.append(f"[hex_blob] {s}")

    if not findings:
        print("No suspicious symbols, flag-shaped strings, or encoded-looking "
              "blobs found in printable strings. Try objdump_disasm or "
              "radare2_info for deeper static analysis.")
        return 0

    # De-duplicate while preserving order, cap output for context budget.
    seen = set()
    for line in findings:
        if line in seen:
            continue
        seen.add(line)
        print(line)
        if len(seen) >= 200:
            print(f"... ({len(findings) - 200} more findings truncated)")
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
