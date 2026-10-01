import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.evidence.models import EvidenceStore
from cypher.flags.extractor import FlagExtractor
from cypher.flags.verifier import FlagVerifier, VerificationStatus


def test_extractor_finds_candidate():
    extractor = FlagExtractor()
    candidates = extractor.find_candidates("some noise CTF{abc_123} more noise")
    assert len(candidates) == 1
    assert candidates[0].full_match == "CTF{abc_123}"
    assert candidates[0].inner_value == "abc_123"


def test_extractor_ignores_non_matching_braces():
    extractor = FlagExtractor()
    candidates = extractor.find_candidates("just a { code block } no flag here")
    assert candidates == []


def test_verifier_confirms_when_found_in_high_relevance_evidence(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    store.add(
        source_tool="strings_extract",
        input_ref="originals/x.bin",
        summary="found candidate",
        raw_output="junk junk CTF{real_flag_here} junk",
        relevance=0.9,
    )
    verifier = FlagVerifier(store)
    extractor = FlagExtractor()
    candidate = extractor.find_candidates("CTF{real_flag_here}")[0]
    result = verifier.verify(candidate)
    assert result.status == VerificationStatus.CONFIRMED
    assert result.candidate.inner_value == "real_flag_here"


def test_verifier_refuses_hallucinated_flag_not_in_evidence(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    store.add(
        source_tool="strings_extract",
        input_ref="originals/x.bin",
        summary="unrelated",
        raw_output="nothing interesting here",
        relevance=0.9,
    )
    verifier = FlagVerifier(store)
    extractor = FlagExtractor()
    candidate = extractor.find_candidates("CTF{made_up_by_llm}")[0]
    result = verifier.verify(candidate)
    assert result.status == VerificationStatus.UNCONFIRMED


def test_verifier_marks_probable_when_low_relevance(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    store.add(
        source_tool="strings_extract",
        input_ref="originals/x.bin",
        summary="low confidence hit",
        raw_output="CTF{maybe_flag}",
        relevance=0.1,
    )
    verifier = FlagVerifier(store, min_relevance=0.3)
    extractor = FlagExtractor()
    candidate = extractor.find_candidates("CTF{maybe_flag}")[0]
    result = verifier.verify(candidate)
    assert result.status == VerificationStatus.PROBABLE
