from __future__ import annotations

from pathlib import Path

from cypher.tools.schemas import SafetyClass, ToolSpec

_SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"
_ENTITY_EXTRACT_SCRIPT = str(_SCRIPT_DIR / "entity_extract.py")


def osint_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="osint_entity_extract",
            category="osint",
            description=(
                "Deterministically extract candidate entities (emails, URLs, domains, "
                "IPv4 addresses, @handles, ISO dates, long hex blobs) from a text file "
                "or tool output, purely by pattern matching — no network access, no "
                "guessing. Use this on challenge descriptions or decoded text to find "
                "leads worth investigating further."
            ),
            executable="python3",
            arg_template=[_ENTITY_EXTRACT_SCRIPT, "{input}"],
            input_types=["text"],
            timeout_seconds=15,
            requires_sandbox=False,
            requires_network=False,
            safety=SafetyClass.SAFE,
        ),
    ]
