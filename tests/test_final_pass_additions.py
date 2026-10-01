import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.ai.mock import MockProvider
from cypher.core.challenge import ChallengeIntake
from cypher.core.investigation import InvestigationLoop
from cypher.core.state import InvestigationState
from cypher.tools.executor import ToolExecutor
from cypher.tools.registry import build_default_registry


def test_pattern_scan_flags_suspicious_symbols_and_flag_shape(tmp_path):
    (tmp_path / "originals").mkdir()
    data = b"\x7fELF" + b"\x00" * 40 + b"strcmp\x00" + b"flag{scan_test}\x00"
    (tmp_path / "originals" / "probe.bin").write_bytes(data)

    registry = build_default_registry()
    executor = ToolExecutor(registry, tmp_path)
    result = executor.execute("suspicious_pattern_scan", "originals/probe.bin")
    assert result.exit_code == 0
    assert "[suspicious_symbol:strcmp] strcmp" in result.stdout
    assert "[flag_shape] flag{scan_test}" in result.stdout


def test_pattern_scan_quiet_on_boring_binary(tmp_path):
    (tmp_path / "originals").mkdir()
    (tmp_path / "originals" / "boring.bin").write_bytes(b"\x00\x01\x02\x03" * 20)
    registry = build_default_registry()
    executor = ToolExecutor(registry, tmp_path)
    result = executor.execute("suspicious_pattern_scan", "originals/boring.bin")
    assert result.exit_code == 0
    assert "No suspicious symbols" in result.stdout


def test_osint_corroboration_links_entity_seen_in_two_evidence_sources(tmp_path):
    """A username appearing in both the challenge description scan AND a
    decoded artifact should be flagged as corroborated, not just found once."""
    src = tmp_path / "chal.txt"
    src.write_text("Contact the operator at agent47@example.com for hints.\n")
    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_path(src, description="OSINT challenge")

    ai = MockProvider()
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    ai.queue_response(json.dumps({"hypotheses": [
        {"statement": "Extract entities from the challenge text.", "category": "osint", "priority": 0.8}
    ]}))
    ai.queue_response(json.dumps({
        "tool": "osint_entity_extract", "input": challenge.files[0].original_name,
        "extra_args": [], "reason": "find leads",
    }))
    ai.queue_response(json.dumps({
        "tool": "strings_extract", "input": challenge.files[0].original_name, "extra_args": [],
    }))
    for _ in range(3):
        ai.queue_response("{}")

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(ai=ai, registry=registry, challenge=challenge, state=state, max_iterations=5)
    final_state = loop.run()

    osint_evidence = [e for e in final_state.evidence.all() if e.source_tool == "osint_entity_extract"]
    assert len(osint_evidence) == 1
    # strings_extract on the same file also contains the email -- that's
    # the second independent source that should trigger corroboration.
    # The osint tool ran FIRST, so this only appears if corroboration is
    # re-checked retroactively as later evidence arrives (not just once
    # at extraction time).
    assert osint_evidence[0].interpretation is not None
    assert "corroboration" in osint_evidence[0].interpretation.lower()
    assert "agent47@example.com" in osint_evidence[0].interpretation


def test_elevated_tools_have_tighter_resource_limits_than_default():
    registry = build_default_registry()
    gdb_spec = registry.get("gdb_batch_run")
    safe_spec = registry.get("file_identify")
    assert gdb_spec.max_memory_bytes is not None
    assert gdb_spec.max_memory_bytes < 512 * 1024 * 1024
    assert gdb_spec.max_cpu_seconds is not None and gdb_spec.max_cpu_seconds <= 10
    # A safe static-analysis tool shouldn't need an artificially tight cap.
    assert safe_spec.max_memory_bytes is None


def test_pwntools_probe_correctly_reports_unavailable_without_pwn_package():
    """Regression test for the is_available() gap: a python3-based tool
    that needs a specific package must not report AVAILABLE just because
    python3 itself exists."""
    registry = build_default_registry()
    spec = registry.get("pwntools_probe")
    assert spec.required_python_packages == ["pwn"]
    import importlib.util
    pwn_installed = importlib.util.find_spec("pwn") is not None
    # Whatever the real state of this machine, is_available() must agree
    # with reality rather than just checking python3 exists.
    assert spec.is_available() == pwn_installed
