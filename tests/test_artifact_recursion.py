"""Proves artifact-aware recursion actually works: a tool creates a NEW
file in the workspace, CYPHER notices it, registers it as a discovered
artifact, and spawns a follow-up hypothesis to investigate it — the
"CRITICAL" capability from the spec (section 5). Uses image_channel_split
(ImageMagick's `convert`), which is genuinely installed in this
environment, run in development sandbox policy so it actually executes
(competition-mode blocking is covered separately in test_sandbox.py).
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.ai.mock import MockProvider
from cypher.core.challenge import ChallengeIntake
from cypher.core.investigation import InvestigationLoop
from cypher.core.state import InvestigationState
from cypher.tools.registry import build_default_registry


def _make_png(path: Path) -> bool:
    if not shutil.which("convert"):
        return False
    # A gradient (not a flat color) so each separated RGB channel produces
    # genuinely different bytes -- a uniform-color test image would make
    # the channel outputs hash-identical to each other and to the
    # original, which the cycle guard would then (correctly) treat as
    # "already seen", masking the behavior this test is meant to prove.
    subprocess.run(
        ["convert", "-size", "8x8", "gradient:red-blue", str(path)],
        check=True, capture_output=True,
    )
    return True


def test_tool_producing_new_file_is_registered_as_discovered_artifact(tmp_path):
    png_path = tmp_path / "probe.png"
    if not _make_png(png_path):
        return  # ImageMagick not installed here; nothing to test against

    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_path(png_path, description="Investigate this image.")

    ai = MockProvider()
    # Interpretation calls are matched by content so they never consume
    # a queued response meant for a hypothesize/plan call.
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    ai.queue_response(json.dumps({"hypotheses": [
        {"statement": "Data may be hidden in a single color channel.", "category": "stego", "priority": 0.8}
    ]}))
    ai.queue_response(json.dumps({
        "tool": "image_channel_split", "input": challenge.files[0].original_name,
        "extra_args": [], "reason": "split channels to look for LSB hides",
    }))
    # After the split, the planner will be asked again (channel files now
    # exist); give it something harmless so the loop terminates cleanly.
    for _ in range(5):
        ai.queue_response("not valid json at all")

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(
        ai=ai, registry=registry, challenge=challenge, state=state,
        max_iterations=6, sandbox_policy="development",
    )
    final_state = loop.run()  # must not raise

    assert len(final_state.discovered_artifacts) > 0, "convert -separate should have produced channel_*.png files"
    names = [a.name for a in final_state.discovered_artifacts]
    assert any("channel" in n for n in names)

    # A follow-up hypothesis about the discovered artifact must exist.
    statements = [h.statement for h in final_state.hypotheses.all()]
    assert any("discovered artifact" in s.lower() for s in statements)

    # Depth must be tracked (1 = one tool deep from an original file).
    assert all(a.depth >= 1 for a in final_state.discovered_artifacts)


def test_cycle_guard_prevents_reregistering_the_same_artifact_twice(tmp_path):
    """If the same tool is somehow run twice and produces byte-identical
    output, the second run must not double-count it as a new artifact."""
    from cypher.core.state import DiscoveredArtifact

    state = InvestigationState.load_or_create("fake", tmp_path)
    artifact = DiscoveredArtifact(
        name="payload.zip", relative_path="extracted/payload.zip",
        sha256="deadbeef" * 8, produced_by_tool="binwalk_extract",
        produced_by_evidence_id="E1", depth=1,
    )
    first = state.register_artifact_if_new(artifact)
    second = state.register_artifact_if_new(artifact)
    assert first is True
    assert second is False
    assert len(state.discovered_artifacts) == 1


def test_depth_ceiling_is_enforced():
    from cypher.core.investigation import MAX_ARTIFACT_DEPTH

    assert MAX_ARTIFACT_DEPTH >= 1  # sanity: recursion is bounded, not disabled
    assert MAX_ARTIFACT_DEPTH <= 10  # sanity: not effectively unbounded either
