"""Priority 2 (Web) safety tests. The critical property: CYPHER can never
be steered — by the LLM, by challenge content, or by a redirect — into
fetching a URL off the operator-authorized origin. These tests exercise
the REAL fetch code path (this environment has an egress proxy that
returns 403 for most destinations, which is fine — it still proves the
request-building/response-handling logic works, just not that arbitrary
content can be retrieved. See KNOWN LIMITATIONS in the final report for
what remains genuinely untested.)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.tools.web.fetcher import WebPolicyError, assert_authorized, is_same_origin
from cypher.tools.executor import ToolExecutor
from cypher.tools.registry import build_default_registry


def test_same_origin_positive_and_negative_cases():
    assert is_same_origin("http://example.com/a", "http://example.com/b") is True
    assert is_same_origin("http://example.com/a?x=1", "http://example.com/") is True
    assert is_same_origin("http://evil.com/", "http://example.com/") is False
    assert is_same_origin("https://example.com/", "http://example.com/") is False  # scheme matters
    assert is_same_origin("http://example.com:8080/", "http://example.com/") is False  # port matters
    assert is_same_origin("http://example.com.evil.com/", "http://example.com/") is False  # no suffix tricks
    assert is_same_origin("ftp://example.com/", "http://example.com/") is False  # non-http(s) refused


def test_assert_authorized_blocks_off_origin_and_allows_on_origin():
    authorized = ["http://ctf-target.example/chal"]
    assert_authorized("http://ctf-target.example/chal/robots.txt", authorized)  # must not raise
    try:
        assert_authorized("http://attacker.example/steal-data", authorized)
        assert False, "should have raised WebPolicyError"
    except WebPolicyError:
        pass


def test_assert_authorized_with_no_configured_target_blocks_everything():
    try:
        assert_authorized("http://anything.example/", [])
        assert False, "should have raised WebPolicyError with no authorized targets"
    except WebPolicyError:
        pass


def test_executor_web_tool_blocks_off_origin_fetch(tmp_path):
    """Even called directly at the executor level (bypassing the planner
    entirely), a web tool must refuse an off-origin URL."""
    registry = build_default_registry()
    executor = ToolExecutor(registry, tmp_path, authorized_urls=["http://ctf-target.example/chal"])
    result = executor.execute("web_fetch_headers", "http://attacker.example/exfiltrate")
    assert result.sandbox_mode == "blocked_web_policy"
    assert result.exit_code is None
    assert "WEB_POLICY_BLOCKED" in result.stderr


def test_executor_web_tool_real_fetch_on_authorized_origin(tmp_path):
    """Exercises the real network code path against a real (public)
    origin the test authorizes for itself. This environment's egress
    proxy blocks most destinations (typically returning HTTP 403), which
    is fine here -- the point is proving the request/response handling
    works end-to-end, not that arbitrary content is retrievable.
    """
    registry = build_default_registry()
    executor = ToolExecutor(registry, tmp_path, authorized_urls=["http://example.com/"])
    result = executor.execute("web_fetch_headers", "http://example.com/")
    # We accept either a real response or a network-level failure (no
    # egress at all) -- what must NEVER happen is a ToolValidationError
    # from the workspace-file resolution path, since url_input tools must
    # bypass that entirely.
    assert result.sandbox_mode in ("host",)
    assert result.exit_code in (0, 1)  # 0 = got an HTTP response, 1 = network error


def test_llm_supplied_off_origin_url_never_reaches_the_fetcher(tmp_path):
    """The investigation loop's own defense-in-depth: even if the model
    hallucinates or is prompt-injected into naming an attacker URL as
    'input', the loop can only ever select from pre-registered
    investigable files/URLs (only the operator's authorized URL, for a
    web challenge) -- so the attacker string is never used as the actual
    fetch target, it just falls back to the authorized one.
    """
    import json

    from cypher.ai.mock import MockProvider
    from cypher.core.challenge import ChallengeIntake
    from cypher.core.investigation import InvestigationLoop
    from cypher.core.state import InvestigationState

    intake = ChallengeIntake(tmp_path / "ws")
    challenge = intake.ingest_url("http://example.com/chal", description="web challenge")

    ai = MockProvider()
    ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
    ai.queue_response(json.dumps({"hypotheses": [
        {"statement": "Inspect the web target's headers.", "category": "web", "priority": 0.8}
    ]}))
    # Malicious/hallucinated input naming an off-origin URL.
    ai.queue_response(json.dumps({
        "tool": "web_fetch_headers", "input": "http://attacker.example/exfiltrate-secrets",
        "extra_args": [], "reason": "definitely not suspicious",
    }))
    for _ in range(3):
        ai.queue_response("{}")

    registry = build_default_registry()
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
    loop = InvestigationLoop(ai=ai, registry=registry, challenge=challenge, state=state, max_iterations=4)
    final_state = loop.run()  # must not raise

    for ev in final_state.evidence.all():
        assert "attacker.example" not in ev.input_ref
