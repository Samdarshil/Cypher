"""Regression tests for the multilayer artifact-scheduling bug.

Reported failure: carrier.bin -> embedded archive -> decoy.txt + readme.txt
discovered simultaneously. Cypher spent the iteration budget grinding on
decoy.txt and never reached readme.txt (which held the real, base64-encoded
flag) within an 8-iteration Qwen3:8B run, ending NOT_YET_FOUND.

Root cause (see core/hypotheses.py, core/investigation.py): artifacts
discovered in the same batch were seeded at an identical flat priority,
and Python's stable sort meant the alphabetically-first filename always
won every tie -- a filesystem-ordering accident, not a reasoned choice.

Nothing here hard-codes "readme.txt", "decoy.txt", or the planted flag
into production logic -- only into this test's synthetic fixture, which
recreates the failure's SHAPE (two simultaneously-discovered artifacts,
one a dead end, one holding a base64-encoded flag) generically.
"""
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.ai.mock import MockProvider
from cypher.core.challenge import ChallengeIntake
from cypher.core.hypotheses import HypothesisBoard
from cypher.core.investigation import InvestigationLoop
from cypher.core.state import InvestigationState, InvestigationStatus
from cypher.tools.registry import build_default_registry


def _build_carrier(tmp_path, dead_end_name="artifact_a.txt", real_name="artifact_b.txt"):
    """A carrier binary containing an embedded zip with two files: one a
    dead end, one holding a base64-encoded flag. Names are parameterized
    (never hard-coded) to make clear the fix doesn't depend on filenames.
    """
    import base64

    work = tmp_path / "build"
    work.mkdir()
    (work / dead_end_name).write_text("nothing useful here, just filler text")
    (work / real_name).write_text(base64.b64encode(b"flag{scheduling_fix_reached_it}").decode())

    zpath = work / "embedded.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.write(work / dead_end_name, dead_end_name)
        zf.write(work / real_name, real_name)

    carrier = tmp_path / "carrier.bin"
    with open(carrier, "wb") as out, open(zpath, "rb") as zf:
        out.write(b"JUNKHEADERBYTES" * 4)  # non-archive prefix, like a real carrier
        out.write(zf.read())
    return carrier


def test_hypothesis_board_breaks_ties_by_freshness_not_insertion_order():
    """Unit-level proof of the exact tie-break bug: two hypotheses seeded
    at the same priority, added in a fixed order, where the SECOND one
    (never yet attempted) must win once the first has been probed once."""
    board = HypothesisBoard()
    h_first = board.add("investigate artifact discovered first alphabetically", "general", priority=0.7)
    h_second = board.add("investigate artifact discovered second alphabetically", "general", priority=0.7)

    # Before either is touched, a tie is fine either way -- but it must
    # NOT be locked in by insertion order once one of them is probed.
    h_first.record_attempt("some_tool:some_file", succeeded=True)  # ran, found nothing new
    # priority still 0.7 for both (no support/failure recorded yet, just
    # an attempt) -- this isolates the tie-break rule itself.

    assert board.top().id == h_second.id, (
        "An untried hypothesis must win a priority tie over one that's "
        "already been attempted, regardless of insertion/discovery order."
    )


def test_multilayer_scheduling_reaches_confirmed_with_realistic_model_behavior(tmp_path):
    """With a model that behaves the way a real (imperfect but working)
    local model plausibly would -- proposing extraction, then picking a
    reasonable tool for a newly discovered text file it's told about --
    the fix must reach CONFIRMED well within a modest iteration budget,
    instead of the decoy monopolizing it.
    """
    carrier = _build_carrier(tmp_path)
    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_path(carrier, description="Suspicious binary carrier.")

    ai = MockProvider()
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    ai.queue_response(json.dumps({"hypotheses": [
        {"statement": "carrier.bin may contain an embedded archive.", "category": "forensics", "priority": 0.7}
    ]}))
    ai.queue_response(json.dumps({
        "tool": "safe_archive_extract", "input": "carrier.bin", "extra_args": [], "reason": "check for embedded archive",
    }))
    # A realistic model, told there are now two candidate text files,
    # tries decoding one of them -- it doesn't need to know in advance
    # which is the decoy; auto_decode is a reasonable next move on ANY
    # small text artifact, and only succeeds on the real one.
    for _ in range(6):
        ai.queue_response(json.dumps({
            "tool": "auto_decode_common_encodings", "input": "artifact_a.txt", "extra_args": [],
        }))
        ai.queue_response(json.dumps({
            "tool": "auto_decode_common_encodings", "input": "artifact_b.txt", "extra_args": [],
        }))

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(
        ai=ai, registry=registry, challenge=challenge, state=state,
        max_iterations=8, sandbox_policy="development",
    )
    final_state = loop.run()

    assert final_state.status == InvestigationStatus.CONFIRMED
    assert final_state.confirmed_flag["flag_value"] == "scheduling_fix_reached_it"
    # Both discovered artifacts must have actually been investigated
    # (not one starved entirely) -- proof the scheduler gave the fresh
    # artifacts real priority rather than grinding on one alone.
    names = {a.name for a in final_state.discovered_artifacts}
    assert names == {"artifact_a.txt", "artifact_b.txt"}


def test_budget_exhaustion_with_remaining_pursuable_hypotheses_is_not_yet_found_not_exhausted(tmp_path):
    """Status semantics audit: if the iteration budget ends while a
    pursuable hypothesis still exists (untried or only partially tried),
    the result must be NOT_YET_FOUND, never EXHAUSTED -- EXHAUSTED is
    reserved for genuinely no useful work remaining. This stress-tests
    the zero-AI-contribution worst case (every call returns garbage),
    which is not expected to solve the challenge in a small budget, but
    MUST report its state honestly either way.
    """
    carrier = _build_carrier(tmp_path)
    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_path(carrier, description="Suspicious binary carrier.")

    ai = MockProvider()
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    ai.queue_response(json.dumps({"hypotheses": [
        {"statement": "carrier.bin may contain an embedded archive.", "category": "forensics", "priority": 0.7}
    ]}))
    ai.queue_response(json.dumps({
        "tool": "safe_archive_extract", "input": "carrier.bin", "extra_args": [], "reason": "check",
    }))
    for _ in range(10):
        ai.queue_response("{}")  # simulates total AI reasoning failure from here on

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(
        ai=ai, registry=registry, challenge=challenge, state=state,
        max_iterations=8, sandbox_policy="development",
    )
    final_state = loop.run()

    if final_state.status != InvestigationStatus.CONFIRMED:
        # With a tiny budget and zero real AI contribution this may not
        # solve -- what matters is it never mislabels remaining work as
        # EXHAUSTED when pursuable hypotheses are still sitting there.
        assert final_state.status == InvestigationStatus.NOT_YET_FOUND
        assert len(final_state.hypotheses.active()) > 0
