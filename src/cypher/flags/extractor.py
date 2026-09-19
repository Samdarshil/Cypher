"""Flag extraction.

Finds candidate flags matching a configured format. Does NOT decide
whether a candidate is real — that's the verifier's job. Extraction should
be generous (find every candidate); verification should be conservative
(confirm almost nothing without proof).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class FlagCandidate:
    full_match: str
    inner_value: str
    source_text_snippet: str
    method_hint: str | None = None  # e.g. "base64", "rot13" — parsed from a
    # leading "[tag]" on the same line, if the producing tool labels its
    # output that way (auto_decode_common_encodings does). Gives the
    # verification chain a provenance label without a full graph DB.


class FlagExtractor:
    def __init__(self, flag_format_regex: str = r"[A-Za-z0-9_]{3,20}\{[^{}\s]{1,200}\}") -> None:
        # Default matches the common CTF{...} / whatever{...} shape.
        self._pattern = re.compile(flag_format_regex)
        self._inner_pattern = re.compile(r"\{([^{}]*)\}")
        self._tag_pattern = re.compile(r"^\[([a-zA-Z0-9_.\-]+)\]\s*")

    def find_candidates(self, text: str) -> list[FlagCandidate]:
        candidates = []
        for match in self._pattern.finditer(text):
            full = match.group(0)
            inner_match = self._inner_pattern.search(full)
            inner = inner_match.group(1) if inner_match else full
            start = max(0, match.start() - 20)
            end = min(len(text), match.end() + 20)

            line_start = text.rfind("\n", 0, match.start()) + 1
            line = text[line_start:match.start()]
            tag_match = self._tag_pattern.match(line)
            method_hint = tag_match.group(1) if tag_match else None

            candidates.append(
                FlagCandidate(
                    full_match=full,
                    inner_value=inner,
                    source_text_snippet=text[start:end],
                    method_hint=method_hint,
                )
            )
        return candidates
