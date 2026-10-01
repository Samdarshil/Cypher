"""Regression test for the multilayer competition false positive:

Cypher investigated a multilayer carrier (embedded ZIP + artifacts,
planted flag CYTHER{multilayer_binwalk_encoding_success}) and incorrectly
promoted an UNRELATED, brute-force-derived XOR string to CONFIRMED before
ever reaching the real flag.

Root cause: single-byte XOR is brute-forced across 255 keys
(tools/crypto/scripts/auto_decode.py::try_single_byte_xor). Over that
many attempts against real byte content, a coincidental flag-shaped
match is a real risk — and the old verifier confirmed on ONE matching
source with no corroboration requirement.

Fix (flags/verifier.py): a candidate whose method_hint indicates it was
recovered via brute-forced single-byte XOR now requires a second,
independent evidence source before CONFIRMED; a solo match is
downgraded to PROBABLE. Deterministic single-guess transforms
(base64/hex/binary/rot-n) are unaffected — this is deliberately narrow.

The planted flag string itself is NOT hard-coded into production code —
only into this test fixture, which recreates the failure shape.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.evidence.models import EvidenceStore
from cypher.flags.extractor import FlagExtractor
from cypher.flags.verifier import FlagVerifier, VerificationStatus


def test_regex_only_candidate_is_not_verified(tmp_path):
    """A string merely matching the flag shape, with no backing evidence
    at all, must never be confirmed."""
    store = EvidenceStore(tmp_path / "evidence")
    verifier = FlagVerifier(store)
    extractor = FlagExtractor()
    candidate = extractor.find_candidates("CYTHER{never_actually_seen_anywhere}")[0]
    result = verifier.verify(candidate)
    assert result.status == VerificationStatus.UNCONFIRMED


def test_decoy_xor_candidate_from_single_source_is_not_confirmed(tmp_path):
    """The exact bug shape: a brute-forced single-byte XOR decode that
    happens to look flag-shaped, found in only ONE evidence source, must
    NOT be promoted to CONFIRMED."""
    store = EvidenceStore(tmp_path / "evidence")
    store.add(
        source_tool="auto_decode_common_encodings",
        input_ref="originals/carrier_layer2.bin",
        summary="brute-force xor scan",
        raw_output="[xor-0x5a] CYTHER{decoy_unrelated_match_by_chance}",
        relevance=0.9,  # this is exactly the auto-assigned relevance that
        # made the old code confirm on a single hit
    )
    verifier = FlagVerifier(store)
    extractor = FlagExtractor()
    candidate = extractor.find_candidates(
        "[xor-0x5a] CYTHER{decoy_unrelated_match_by_chance}"
    )[0]
    assert candidate.method_hint == "xor-0x5a"

    result = verifier.verify(candidate)
    assert result.status != VerificationStatus.CONFIRMED
    assert result.status == VerificationStatus.PROBABLE


def test_properly_evidenced_multilayer_flag_is_confirmed(tmp_path):
    """The real planted flag, correctly recovered and corroborated by two
    independent evidence sources (e.g. the binwalk-extracted layer AND a
    direct strings hit on the decoded artifact), must still confirm."""
    store = EvidenceStore(tmp_path / "evidence")
    store.add(
        source_tool="safe_archive_extract",
        input_ref="originals/carrier.zip",
        summary="extracted embedded payload",
        raw_output="extracted: layer2/notes.txt containing "
                   "CYTHER{multilayer_binwalk_encoding_success}",
        relevance=0.9,
    )
    store.add(
        source_tool="strings_extract",
        input_ref="extracted/layer2/notes.txt",
        summary="strings on the extracted artifact",
        raw_output="junk junk CYTHER{multilayer_binwalk_encoding_success} junk",
        relevance=0.9,
    )
    verifier = FlagVerifier(store)
    extractor = FlagExtractor()
    candidate = extractor.find_candidates(
        "CYTHER{multilayer_binwalk_encoding_success}"
    )[0]
    result = verifier.verify(candidate)
    assert result.status == VerificationStatus.CONFIRMED
    assert result.candidate.inner_value == "multilayer_binwalk_encoding_success"


def test_decoy_never_beats_real_flag_in_full_extraction_pass(tmp_path):
    """End-to-end shape of the actual bug: a single evidence blob
    containing BOTH the real (single-source) flag and a single-source
    brute-force decoy. The decoy must not confirm just because it's a
    valid-looking format match; only a corroborated candidate may."""
    store = EvidenceStore(tmp_path / "evidence")
    combined_output = (
        "[xor-0x5a] CYTHER{decoy_unrelated_match_by_chance}\n"
        "[xor-0x37] CYTHER{multilayer_binwalk_encoding_success}\n"
    )
    store.add(
        source_tool="auto_decode_common_encodings",
        input_ref="originals/carrier_layer2.bin",
        summary="brute-force xor scan, multiple candidates",
        raw_output=combined_output,
        relevance=0.9,
    )
    # A second, independent source only corroborates the REAL flag.
    store.add(
        source_tool="strings_extract",
        input_ref="originals/carrier_layer2.bin",
        summary="strings hit on the same artifact",
        raw_output="CYTHER{multilayer_binwalk_encoding_success}",
        relevance=0.7,
    )

    verifier = FlagVerifier(store)
    extractor = FlagExtractor()
    candidates = extractor.find_candidates(combined_output)
    assert len(candidates) == 2

    results = [verifier.verify(c) for c in candidates]
    statuses_by_value = {r.candidate.inner_value: r.status for r in results}

    assert statuses_by_value["decoy_unrelated_match_by_chance"] != VerificationStatus.CONFIRMED
    assert statuses_by_value["multilayer_binwalk_encoding_success"] == VerificationStatus.CONFIRMED
