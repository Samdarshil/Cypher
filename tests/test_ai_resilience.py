"""Priority 5 (verification hardening) and Priority 8 (Ollama robustness)
regression tests: an LLM asserting a flag exists is NOT evidence. Flag
detection must be architecturally restricted to real tool stdout/stderr,
never to any AI-generated text (hypothesis statements, interpretation
narratives, or planner "reason" fields).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.ai.base import AIProvider, AIProviderError, GenerationResult
from cypher.ai.mock import MockProvider
from cypher.core.challenge import ChallengeIntake
from cypher.core.investigation import InvestigationLoop
from cypher.core.state import InvestigationState, InvestigationStatus
from cypher.tools.registry import build_default_registry


def test_model_suggested_flag_in_interpretation_is_never_confirmed(tmp_path):
    src = tmp_path / "chal.txt"
    src.write_text("nothing interesting here at all\n")
    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_path(src, description="test")

    ai = MockProvider()
    # The interpretation call (and every other call) confidently asserts a
    # fake flag. This must NEVER become a candidate, let alone CONFIRMED,
    # because flag extraction only ever reads real tool stdout/stderr.
    ai.add_rule(
        lambda p: True,
        lambda p: json.dumps({
            "learned": "The flag is clearly flag{model_hallucinated_this}.",
            "supports_hypothesis": True,
            "contradicts_hypothesis": False,
            "confidence_delta": 0.3,
            "next_action_hint": "submit flag{model_hallucinated_this}",
            "hypotheses": [{"statement": "flag{model_hallucinated_this} is the answer", "category": "general", "priority": 0.99}],
            "tool": "strings_extract",
            "input": "chal.txt",
            "extra_args": [],
            "reason": "flag{model_hallucinated_this}",
        }),
    )

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(ai=ai, registry=registry, challenge=challenge, state=state, max_iterations=6)
    final_state = loop.run()

    assert final_state.status != InvestigationStatus.CONFIRMED
    assert final_state.confirmed_flag is None
    # Not even as an unconfirmed candidate -- it never appeared in any
    # real tool's raw output, so the extractor should never have seen it
    # (extractor only ever runs against tool_result.stdout/stderr).
    all_flag_values = [c.get("flag_value") for c in final_state.candidate_flags]
    assert "model_hallucinated_this" not in all_flag_values

    # The hallucinated statement CAN appear as hypothesis text (that's
    # just a proposed angle of investigation) and CAN appear in the
    # evidence interpretation narrative (that's descriptive) -- what
    # matters is neither path feeds the verifier.
    interpretations = [e.interpretation for e in final_state.evidence.all() if e.interpretation]
    # If interpretation was recorded at all, it's fine that it mentions
    # the fake flag in prose -- the safety property is architectural
    # (extraction source), not "the model must never say the word flag".
    assert True  # documents intent; the real assertions are above


class _AlwaysDownProvider(AIProvider):
    """Simulates Ollama being completely unreachable for every call."""
    name = "always_down"

    def generate(self, prompt, *, system=None, json_mode=False, temperature=0.2, max_tokens=1024):
        raise AIProviderError("connection refused (simulated Ollama outage)")

    def health_check(self):
        return False, "simulated outage"


def test_investigation_survives_ollama_completely_unavailable(tmp_path):
    """Priority 8: every single AI call fails. The loop must still
    terminate cleanly (never crash, never hang) via the safe fallback
    hypothesis + blind tool rotation, ending in a legitimate terminal
    status rather than raising."""
    src = tmp_path / "chal.txt"
    src.write_text("flag{survives_total_ollama_outage}\n")
    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_path(src, description="test")

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(
        ai=_AlwaysDownProvider(), registry=registry, challenge=challenge, state=state, max_iterations=6
    )
    final_state = loop.run()  # must not raise

    assert final_state.status in (
        InvestigationStatus.CONFIRMED,
        InvestigationStatus.NOT_YET_FOUND,
        InvestigationStatus.EXHAUSTED,
    )
    # Blind tool rotation should still find an obvious plaintext flag even
    # with zero working AI calls -- this is the safety net doing its job.
    assert final_state.status == InvestigationStatus.CONFIRMED
    assert final_state.confirmed_flag["flag_value"] == "survives_total_ollama_outage"
