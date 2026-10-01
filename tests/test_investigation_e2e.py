"""End-to-end vertical slice test.

Challenge -> Intake -> AI (mocked) -> Hypothesis -> Tool selection ->
Controlled execution -> Evidence -> Flag extraction -> Verification ->
CONFIRMED result. No live Ollama or Docker required, so this runs in any
environment while still exercising the real executor and real coreutils
tools against a synthetic local challenge.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.ai.mock import MockProvider
from cypher.core.challenge import ChallengeIntake
from cypher.core.investigation import InvestigationLoop
from cypher.core.state import InvestigationState, InvestigationStatus
from cypher.tools.registry import build_default_registry


def _make_challenge(tmp_path):
    src = tmp_path / "challenge.txt"
    src.write_text("random preamble text\nCTF{mock_end_to_end_flag}\ntrailing noise\n")
    intake = ChallengeIntake(tmp_path / "workspaces")
    return intake.ingest_path(src, description="A misc warm-up challenge. Find the flag.")


def _scripted_provider(challenge):
    """Programs the mock model to behave like a competent small local model:
    1st call -> propose one hypothesis
    2nd call -> select strings_extract on the challenge file
    """
    ai = MockProvider()
    # Interpretation calls are matched by content so they never consume
    # a queued response meant for a hypothesize/plan call.
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    ai.queue_response(
        json.dumps(
            {
                "hypotheses": [
                    {
                        "statement": "Flag may be plaintext or embedded as a string in the file.",
                        "category": "general",
                        "priority": 0.8,
                    }
                ]
            }
        )
    )
    file_name = challenge.files[0].original_name
    ai.queue_response(
        json.dumps(
            {
                "tool": "strings_extract",
                "input": file_name,
                "extra_args": [],
                "reason": "extract printable strings to look for a flag pattern",
            }
        )
    )
    return ai


def test_full_loop_reaches_confirmed(tmp_path):
    challenge = _make_challenge(tmp_path)
    ai = _scripted_provider(challenge)
    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)

    loop = InvestigationLoop(ai=ai, registry=registry, challenge=challenge, state=state, max_iterations=5)
    final_state = loop.run()

    assert final_state.status == InvestigationStatus.CONFIRMED
    assert final_state.confirmed_flag is not None
    assert final_state.confirmed_flag["flag_value"] == "mock_end_to_end_flag"
    assert final_state.confirmed_flag["full_flag"] == "CTF{mock_end_to_end_flag}"

    # Resumability: state.json must exist and reload cleanly.
    state_path = challenge.workspace / "state.json"
    assert state_path.exists()
    reloaded = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    assert reloaded.status == InvestigationStatus.CONFIRMED
    assert reloaded.confirmed_flag["flag_value"] == "mock_end_to_end_flag"


def test_loop_never_confirms_when_flag_absent(tmp_path):
    src = tmp_path / "challenge2.txt"
    src.write_text("nothing interesting in this file at all\n")
    intake = ChallengeIntake(tmp_path / "workspaces2")
    challenge = intake.ingest_path(src, description="Empty decoy challenge.")

    ai = MockProvider()
    # Interpretation calls are matched by content so they never consume
    # a queued response meant for a hypothesize/plan call.
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    ai.queue_response(
        json.dumps(
            {"hypotheses": [{"statement": "check strings", "category": "general", "priority": 0.7}]}
        )
    )
    for _ in range(5):
        ai.queue_response(
            json.dumps(
                {
                    "tool": "strings_extract",
                    "input": challenge.files[0].original_name,
                    "extra_args": [],
                    "reason": "check",
                }
            )
        )

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(ai=ai, registry=registry, challenge=challenge, state=state, max_iterations=5)
    final_state = loop.run()

    assert final_state.status != InvestigationStatus.CONFIRMED
    assert final_state.confirmed_flag is None
