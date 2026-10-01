"""The showcase test for spec section 5 (artifact-aware investigation):

    challenge.zip -> safe_archive_extract -> secret.txt (discovered artifact)
        -> auto_decode_common_encodings -> flag{...} -> CONFIRMED

Two hops of recursion, two competing hypotheses (archive vs direct-file),
and a full verification chain, all exercised for real (no internal
shortcuts) through InvestigationLoop.run().
"""
import base64
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.ai.mock import MockProvider
from cypher.core.challenge import ChallengeIntake
from cypher.core.investigation import InvestigationLoop
from cypher.core.state import InvestigationState, InvestigationStatus
from cypher.tools.registry import build_default_registry


def _build_nested_challenge(tmp_path) -> Path:
    inner = tmp_path / "secret.txt"
    inner.write_text(base64.b64encode(b"flag{nested_archive_recursion_works}").decode())
    # Deliberately NOT a .zip suffix: ChallengeIntake auto-extracts known
    # archive extensions at ingest time (by design, for top-level
    # archives), which would short-circuit this test before the
    # investigation loop even starts. Naming it .dat forces the
    # investigation loop's own tool-driven extraction (safe_archive_extract,
    # which detects zip/tar by content, not extension) to do the real work
    # -- which is what this test is actually meant to prove.
    zpath = tmp_path / "challenge.dat"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.write(inner, "secret.txt")
    return zpath


def test_full_recursive_chain_zip_to_base64_to_confirmed_flag(tmp_path):
    zpath = _build_nested_challenge(tmp_path)
    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_path(zpath, description="Something is hidden in this archive.")

    ai = MockProvider()
    # Interpretation calls are matched by content so they never consume
    # a queued response meant for a hypothesize/plan call.
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    # H1: it's an archive worth extracting. H2 (weaker, decoy): maybe the
    # zip bytes themselves are directly meaningful -- a realistic
    # competing hypothesis a model might also propose.
    ai.queue_response(json.dumps({"hypotheses": [
        {"statement": "This is an archive; extract it to find hidden files.", "category": "forensics", "priority": 0.85},
        {"statement": "The raw archive bytes might directly contain the flag.", "category": "general", "priority": 0.3},
    ]}))
    # First tool selection: extract the archive.
    ai.queue_response(json.dumps({
        "tool": "safe_archive_extract", "input": challenge.files[0].original_name,
        "extra_args": [], "reason": "it's a zip, extract to look inside",
    }))
    # Second tool selection: decode the newly discovered secret.txt.
    ai.queue_response(json.dumps({
        "tool": "auto_decode_common_encodings", "input": "secret.txt",
        "extra_args": [], "reason": "decode the extracted file's contents",
    }))
    for _ in range(5):
        ai.queue_response(json.dumps({"tool": "strings_extract", "input": "secret.txt", "extra_args": []}))

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(
        ai=ai, registry=registry, challenge=challenge, state=state,
        max_iterations=8, sandbox_policy="development",
    )
    final_state = loop.run()

    assert final_state.status == InvestigationStatus.CONFIRMED
    assert final_state.confirmed_flag["flag_value"] == "nested_archive_recursion_works"
    assert final_state.confirmed_flag["method"] == "base64"

    # The recursion actually happened: secret.txt must be a tracked,
    # depth-1 discovered artifact traceable back to the extraction tool.
    names = {a.name: a for a in final_state.discovered_artifacts}
    assert "secret.txt" in names
    assert names["secret.txt"].depth == 1
    assert names["secret.txt"].produced_by_tool == "safe_archive_extract"

    # The weaker decoy hypothesis must NOT have won or been mistaken for
    # the source of the flag.
    winning_hyp = next(h for h in final_state.hypotheses.all() if h.status.value == "confirmed")
    assert "extract" in winning_hyp.statement.lower()
