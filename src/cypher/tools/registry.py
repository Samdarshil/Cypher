"""Tool registry.

Holds every tool CYPHER is allowed to invoke. Starts with the small
"General" category from the spec (file, strings, grep, xxd), plus
forensics, stego, crypto, and reverse-engineering specialist sets.
Every tool checks is_available() at use time, so an uninstalled binary
just doesn't show up as a selectable option instead of crashing anything —
run `cypher doctor` to see what's actually usable on this machine.
"""
from __future__ import annotations

from .schemas import SafetyClass, ToolSpec


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"Tool '{spec.name}' already registered.")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list(self, category: str | None = None, available_only: bool = False) -> list[ToolSpec]:
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        if available_only:
            tools = [t for t in tools if t.is_available()]
        return tools

    def describe_for_prompt(self, category: str | None = None) -> str:
        """Render available tools as compact text for inclusion in an LLM
        prompt, so the model can only ever choose from what's registered
        (and actually installed).
        """
        lines = []
        for tool in self.list(category=category, available_only=True):
            lines.append(f"- {tool.name} ({tool.category}): {tool.description}")
        return "\n".join(lines) if lines else "(no tools currently available)"


def build_default_registry() -> ToolRegistry:
    reg = ToolRegistry()

    reg.register(
        ToolSpec(
            name="file_identify",
            category="general",
            description="Identify file type via magic bytes. Args: none, takes {input}.",
            executable="file",
            arg_template=["-b", "{input}"],
            input_types=["any"],
            timeout_seconds=10,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        )
    )
    reg.register(
        ToolSpec(
            name="strings_extract",
            category="general",
            description=(
                "Extract printable ASCII strings (min length 4) from a file. "
                "Good first step for any binary/image/media file."
            ),
            executable="strings",
            arg_template=["-n", "4", "{input}"],
            input_types=["any"],
            timeout_seconds=20,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        )
    )
    reg.register(
        ToolSpec(
            name="grep_pattern",
            category="general",
            description=(
                "Search a file for a fixed substring/regex pattern. "
                "Provide the pattern as the single extra argument."
            ),
            executable="grep",
            arg_template=["-a", "-o", "-E", "{extra}", "{input}"],
            allowed_extra_args=True,
            allowed_extra_arg_pattern=r"^[A-Za-z0-9_{}\[\]().*+?^$|:=/\\-]{1,128}$",
            input_types=["any"],
            timeout_seconds=15,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        )
    )
    reg.register(
        ToolSpec(
            name="hexdump_view",
            category="general",
            description="Show a hex + ASCII dump of the first bytes of a file (header inspection).",
            executable="xxd",
            arg_template=["-l", "512", "{input}"],
            input_types=["any"],
            timeout_seconds=10,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        )
    )

    reg.register(
        ToolSpec(
            name="ripgrep_pattern",
            category="general",
            description=(
                "Same as grep_pattern but faster on large files/directories and handles "
                "binary files more predictably. Provide the pattern as the single extra "
                "argument."
            ),
            executable="rg",
            arg_template=["-a", "-o", "{extra}", "{input}"],
            allowed_extra_args=True,
            allowed_extra_arg_pattern=r"^[A-Za-z0-9_{}\[\]().*+?^$|:=/\\-]{1,128}$",
            input_types=["any"],
            timeout_seconds=15,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        )
    )

    from cypher.tools.forensics.specs import forensics_tools
    from cypher.tools.stego.specs import stego_tools
    from cypher.tools.crypto.specs import crypto_tools
    from cypher.tools.reverse.specs import reverse_tools
    from cypher.tools.audio.specs import audio_tools
    from cypher.tools.web.specs import web_tools
    from cypher.tools.osint.specs import osint_tools

    for spec in [
        *forensics_tools(), *stego_tools(), *crypto_tools(), *reverse_tools(),
        *audio_tools(), *web_tools(), *osint_tools(),
    ]:
        reg.register(spec)

    return reg
