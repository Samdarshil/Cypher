import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from cypher.tools.executor import ToolExecutor, ToolValidationError
from cypher.tools.registry import build_default_registry


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "originals").mkdir()
    (tmp_path / "originals" / "sample.txt").write_text("hello CTF{not_a_real_flag} world\n")
    return tmp_path


def test_file_identify(workspace):
    registry = build_default_registry()
    executor = ToolExecutor(registry, workspace)
    result = executor.execute("file_identify", "originals/sample.txt")
    assert result.exit_code == 0
    assert "text" in result.stdout.lower() or "ascii" in result.stdout.lower()


def test_unknown_tool_rejected(workspace):
    registry = build_default_registry()
    executor = ToolExecutor(registry, workspace)
    with pytest.raises(ToolValidationError):
        executor.execute("nonexistent_tool", "originals/sample.txt")


def test_path_traversal_rejected(workspace):
    registry = build_default_registry()
    executor = ToolExecutor(registry, workspace)
    with pytest.raises(ToolValidationError):
        executor.execute("file_identify", "../../../../etc/passwd")


def test_missing_file_rejected(workspace):
    registry = build_default_registry()
    executor = ToolExecutor(registry, workspace)
    with pytest.raises(ToolValidationError):
        executor.execute("file_identify", "originals/does_not_exist.txt")


def test_extra_args_pattern_enforced(workspace):
    registry = build_default_registry()
    executor = ToolExecutor(registry, workspace)
    # A grep pattern with disallowed characters (e.g. shell metacharacters
    # outside the allow-listed set) must be rejected before exec.
    with pytest.raises(ToolValidationError):
        executor.execute("grep_pattern", "originals/sample.txt", ["; rm -rf /"])


def test_grep_pattern_finds_flag_shape(workspace):
    registry = build_default_registry()
    executor = ToolExecutor(registry, workspace)
    result = executor.execute(
        "grep_pattern", "originals/sample.txt", [r"[A-Za-z0-9_]+\{[^}]+\}"]
    )
    assert result.exit_code == 0
    assert "CTF{not_a_real_flag}" in result.stdout


def test_tool_that_does_not_accept_extras_rejects_them(workspace):
    registry = build_default_registry()
    executor = ToolExecutor(registry, workspace)
    with pytest.raises(ToolValidationError):
        executor.execute("file_identify", "originals/sample.txt", ["-extra"])
