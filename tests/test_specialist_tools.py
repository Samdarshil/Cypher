import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.ai.mock import MockProvider
from cypher.core.challenge import ChallengeIntake
from cypher.core.investigation import InvestigationLoop
from cypher.core.state import InvestigationState, InvestigationStatus
from cypher.tools.executor import ToolExecutor
from cypher.tools.registry import build_default_registry


def test_registry_has_expected_specialist_categories():
    registry = build_default_registry()
    categories = {t.category for t in registry.list()}
    for expected in ("general", "forensics", "stego", "crypto", "reverse", "audio"):
        assert expected in categories, f"missing category: {expected}"
    names = {t.name for t in registry.list()}
    for expected_tool in (
        "exif_metadata", "binwalk_scan", "steghide_info", "zsteg_scan",
        "auto_decode_common_encodings", "elf_headers", "audio_metadata",
    ):
        assert expected_tool in names


def test_auto_decode_tool_solves_base64_via_registry(tmp_path):
    (tmp_path / "originals").mkdir()
    payload = base64.b64encode(b"flag{registry_wired_b64}").decode()
    (tmp_path / "originals" / "enc.txt").write_text(payload)

    registry = build_default_registry()
    executor = ToolExecutor(registry, tmp_path)
    result = executor.execute("auto_decode_common_encodings", "originals/enc.txt")
    assert result.exit_code == 0
    assert "flag{registry_wired_b64}" in result.stdout


def test_auto_decode_rot13_does_not_produce_multiple_conflicting_winners(tmp_path):
    (tmp_path / "originals").mkdir()
    # rot13 of "this is rot13: flag{rot13_ok}"
    (tmp_path / "originals" / "rot.txt").write_text("guvf vf ebg13: synt{ebg13_bx}")

    registry = build_default_registry()
    executor = ToolExecutor(registry, tmp_path)
    result = executor.execute("auto_decode_common_encodings", "originals/rot.txt")
    rot_lines = [l for l in result.stdout.splitlines() if l.startswith("[rot")]
    # Must not spuriously "confirm" all 25 shifts just because braces pass
    # through unshifted -- exactly one real winner expected here.
    assert len(rot_lines) == 1
    assert "flag{rot13_ok}" in rot_lines[0]


def test_full_loop_solves_xor_encoded_flag_with_corroboration(tmp_path):
    """Single-byte XOR is brute-forced across 255 keys (see
    flags/verifier.py), so a solo match is only PROBABLE, not CONFIRMED —
    it needs a second independent evidence source. Two files carrying the
    same XOR-encoded flag (a realistic multi-artifact scenario) give the
    loop two separate real decodes to corroborate against each other.
    See test_verifier_hardening.py for the focused unit-level proof of
    the underlying rule, including the exact false-positive this guards
    against.
    """
    chal_dir = tmp_path / "chal"
    chal_dir.mkdir()
    raw = bytes(b ^ 0x37 for b in b"flag{full_loop_xor_ok}")
    (chal_dir / "part_a.bin").write_bytes(raw)
    (chal_dir / "part_b.bin").write_bytes(raw)  # same content, different artifact
    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_path(chal_dir, description="Single-byte XOR encoded flag, split across two files.")

    ai = MockProvider()
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    ai.queue_response(json.dumps({"hypotheses": [
        {"statement": "Files are XOR-encoded with a single byte key.", "category": "crypto", "priority": 0.9}
    ]}))
    ai.queue_response(json.dumps({
        "tool": "auto_decode_common_encodings", "input": "part_a.bin",
        "extra_args": [], "reason": "try common encodings including single-byte xor",
    }))
    ai.queue_response(json.dumps({
        "tool": "auto_decode_common_encodings", "input": "part_b.bin",
        "extra_args": [], "reason": "check the second artifact too",
    }))

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(ai=ai, registry=registry, challenge=challenge, state=state, max_iterations=5)
    final_state = loop.run()

    assert final_state.status == InvestigationStatus.CONFIRMED
    assert final_state.confirmed_flag["flag_value"] == "full_loop_xor_ok"
