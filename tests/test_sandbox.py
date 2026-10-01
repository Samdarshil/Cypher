import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.tools.executor import ToolExecutor
from cypher.tools.registry import build_default_registry


def _workspace(tmp_path):
    (tmp_path / "originals").mkdir()
    (tmp_path / "originals" / "sample.txt").write_text("hello\n")
    return tmp_path


def _find_available_sandboxed_tool(registry):
    """Pick any registered, actually-installed tool with requires_sandbox=True,
    so these tests exercise real behavior instead of silently skipping when
    a specific named tool (e.g. binwalk) isn't installed in this environment.
    """
    for tool in registry.list(available_only=True):
        if tool.requires_sandbox:
            return tool
    return None


def test_safe_tool_never_uses_docker_even_if_enabled(tmp_path):
    ws = _workspace(tmp_path)
    registry = build_default_registry()
    executor = ToolExecutor(registry, ws, use_docker=True)
    # file_identify has requires_sandbox=False -> should always run natively.
    result = executor.execute("file_identify", "originals/sample.txt")
    assert result.sandbox_mode == "host"
    assert result.exit_code == 0


def test_competition_mode_blocks_sandboxed_tool_when_docker_unavailable(tmp_path):
    ws = _workspace(tmp_path)
    registry = build_default_registry()
    tool = _find_available_sandboxed_tool(registry)
    assert tool is not None, "test needs at least one installed requires_sandbox=True tool"

    executor = ToolExecutor(registry, ws, use_docker=True, sandbox_policy="competition")
    assert executor.docker_available() is False, "this test environment has no docker binary"

    result = executor.execute(tool.name, "originals/sample.txt")
    # Competition mode must BLOCK, never silently run on the host.
    assert result.sandbox_mode == "blocked_sandbox_required"
    assert result.exit_code is None
    assert "BLOCKED_SANDBOX_REQUIRED" in result.stderr
    assert result.argv == []  # nothing was ever actually executed


def test_development_mode_falls_back_to_host_when_docker_unavailable(tmp_path):
    ws = _workspace(tmp_path)
    registry = build_default_registry()
    tool = _find_available_sandboxed_tool(registry)
    assert tool is not None

    executor = ToolExecutor(registry, ws, use_docker=True, sandbox_policy="development")
    assert executor.docker_available() is False

    result = executor.execute(tool.name, "originals/sample.txt")
    # Development mode explicitly permits a controlled host fallback,
    # visibly labeled as such rather than pretending to be sandboxed.
    assert result.sandbox_mode == "host-fallback"
    assert result.argv  # it actually ran


def test_investigation_loop_survives_a_blocked_sandbox_tool(tmp_path):
    """A BLOCKED_SANDBOX_REQUIRED result must be treated as informative
    failure feedback by the investigation loop, never a crash."""
    import json

    from cypher.ai.mock import MockProvider
    from cypher.core.challenge import ChallengeIntake
    from cypher.core.investigation import InvestigationLoop
    from cypher.core.state import InvestigationState

    registry = build_default_registry()
    tool = _find_available_sandboxed_tool(registry)
    assert tool is not None

    src = tmp_path / "chal.txt"
    src.write_text("nothing useful here\n")
    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_path(src, description="test")

    ai = MockProvider()
    # Interpretation calls are matched by content so they never consume
    # a queued response meant for a hypothesize/plan call.
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    ai.queue_response(json.dumps({"hypotheses": [{"statement": "x", "category": "general", "priority": 0.9}]}))
    ai.queue_response(json.dumps({
        "tool": tool.name, "input": challenge.files[0].original_name, "extra_args": [], "reason": "test"
    }))

    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(
        ai=ai, registry=registry, challenge=challenge, state=state,
        max_iterations=3, use_docker=True, sandbox_policy="competition",
    )
    final_state = loop.run()  # must not raise
    assert final_state.status.value != "CONFIRMED"
    # The block should be recorded as evidence, not silently dropped.
    blocked_evidence = [e for e in final_state.evidence.all() if "BLOCKED_SANDBOX_REQUIRED" in e.summary]
    assert len(blocked_evidence) >= 1


def test_docker_argv_construction_is_correct(tmp_path):
    ws = _workspace(tmp_path)
    registry = build_default_registry()
    executor = ToolExecutor(registry, ws, use_docker=True, docker_image="cypher-sandbox")
    spec = registry.get("file_identify")
    resolved = ws / "originals" / "sample.txt"
    argv = executor._build_docker_argv(spec, resolved, [])
    assert argv[0:3] == ["docker", "run", "--rm"]
    assert "--network" in argv and "none" in argv
    assert "-v" in argv
    mount_arg = argv[argv.index("-v") + 1]
    assert mount_arg == f"{ws.resolve()}:/work"
    assert "cypher-sandbox" in argv
    # the tool's own argv must use a path RELATIVE to /work, not the host
    # absolute path (that path won't exist inside the container).
    assert "originals/sample.txt" in argv
    assert str(resolved) not in argv


def test_docker_network_none_by_default_but_bridge_if_tool_requires_network(tmp_path):
    ws = _workspace(tmp_path)
    registry = build_default_registry()
    executor = ToolExecutor(registry, ws, use_docker=True)
    spec = registry.get("binwalk_scan")
    argv = executor._build_docker_argv(spec, ws / "originals" / "sample.txt", [])
    net_idx = argv.index("--network")
    assert argv[net_idx + 1] == "none"  # binwalk_scan does not require network
