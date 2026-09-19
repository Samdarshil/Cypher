"""Tool specification schema.

The LLM never gets a raw shell. It selects a registered tool by name and
supplies arguments; the executor validates everything against the spec
before anything runs. This file defines what a valid tool declaration
looks like.
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from enum import Enum


class SafetyClass(str, Enum):
    SAFE = "safe"                 # read-only inspection, no network, no writes outside workspace
    MODERATE = "moderate"         # may write derived files inside workspace
    ELEVATED = "elevated"         # e.g. dynamic execution/emulation of untrusted binaries


@dataclass
class ToolSpec:
    name: str
    category: str
    description: str
    executable: str  # binary name resolved via PATH, never a full attacker-influenced path
    arg_template: list[str]
    # arg_template uses placeholders like "{input}" and "{extra}"; "{extra}"
    # values must each match allowed_extra_arg_pattern if extras are permitted.
    allowed_extra_args: bool = False
    allowed_extra_arg_pattern: str = r"^[A-Za-z0-9_.:=/-]{1,64}$"
    input_types: list[str] = field(default_factory=list)
    output_types: list[str] = field(default_factory=lambda: ["text"])
    timeout_seconds: int = 30
    max_output_bytes: int = 2_000_000
    requires_sandbox: bool = True
    requires_network: bool = False
    safety: SafetyClass = SafetyClass.SAFE
    url_input: bool = False  # True: {input} is a URL (validated against the
    # challenge's authorized origin), not a workspace file path. Handled by
    # a dedicated code path in the executor, not by spawning a subprocess.
    common_followups: list[str] = field(default_factory=list)  # tool names
    # that are typically useful right after this one succeeds — advisory
    # metadata surfaced to the planner, not enforced.
    max_cpu_seconds: int | None = None    # None = use executor default
    max_memory_bytes: int | None = None   # None = use executor default;
    # override downward for ELEVATED tools (e.g. dynamic execution stubs)
    # so a misbehaving challenge binary can't consume the whole box even
    # within its own timeout window.
    required_python_packages: list[str] = field(default_factory=list)
    # For python3-based tools: package names that must actually be
    # importable, not just "python3 exists on PATH". Without this,
    # e.g. pwntools_probe would report AVAILABLE even with pwntools
    # not installed, only failing later at runtime.

    def is_available(self) -> bool:
        if self.url_input:
            return True  # no external binary dependency
        if shutil.which(self.executable) is None:
            return False
        if self.required_python_packages:
            import importlib.util

            for pkg in self.required_python_packages:
                if importlib.util.find_spec(pkg) is None:
                    return False
        return True

    def validate_extra_args(self, extra_args: list[str]) -> tuple[bool, str]:
        if extra_args and not self.allowed_extra_args:
            return False, f"Tool '{self.name}' does not accept extra arguments."
        pattern = re.compile(self.allowed_extra_arg_pattern)
        for arg in extra_args:
            if not pattern.match(arg):
                return False, f"Argument {arg!r} is not permitted for tool '{self.name}'."
        return True, ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "executable": self.executable,
            "input_types": self.input_types,
            "output_types": self.output_types,
            "timeout_seconds": self.timeout_seconds,
            "requires_sandbox": self.requires_sandbox,
            "requires_network": self.requires_network,
            "safety": self.safety.value,
            "available": self.is_available(),
        }
