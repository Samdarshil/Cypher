from __future__ import annotations

from cypher.tools.schemas import SafetyClass, ToolSpec


def web_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="web_fetch_headers",
            category="web",
            description=(
                "Fetch HTTP response headers only (status code, server, cookies, "
                "security headers, redirects) for the authorized challenge URL or "
                "a same-origin path on it. Always start here for a web challenge."
            ),
            executable="__web__",
            arg_template=[],
            input_types=["url"],
            output_types=["text"],
            timeout_seconds=15,
            requires_sandbox=False,
            requires_network=True,
            safety=SafetyClass.SAFE,
            url_input=True,
            common_followups=["web_fetch_body", "web_fetch_robots"],
        ),
        ToolSpec(
            name="web_fetch_body",
            category="web",
            description=(
                "Fetch the full HTTP response body (HTML/JSON/text, truncated if huge) "
                "for the authorized challenge URL or a same-origin path on it. Use this "
                "to read page source, inline scripts, comments, and forms."
            ),
            executable="__web__",
            arg_template=[],
            input_types=["url"],
            output_types=["text"],
            timeout_seconds=15,
            requires_sandbox=False,
            requires_network=True,
            safety=SafetyClass.SAFE,
            url_input=True,
            common_followups=["grep_pattern", "auto_decode_common_encodings"],
        ),
        ToolSpec(
            name="web_fetch_robots",
            category="web",
            description=(
                "Fetch /robots.txt from the authorized target's origin — often reveals "
                "hidden/disallowed paths worth investigating in a CTF."
            ),
            executable="__web__",
            arg_template=[],
            input_types=["url"],
            output_types=["text"],
            timeout_seconds=15,
            requires_sandbox=False,
            requires_network=True,
            safety=SafetyClass.SAFE,
            url_input=True,
            common_followups=["web_fetch_body"],
        ),
        ToolSpec(
            name="web_fetch_sitemap",
            category="web",
            description="Fetch /sitemap.xml from the authorized target's origin, if present.",
            executable="__web__",
            arg_template=[],
            input_types=["url"],
            output_types=["text"],
            timeout_seconds=15,
            requires_sandbox=False,
            requires_network=True,
            safety=SafetyClass.SAFE,
            url_input=True,
            common_followups=["web_fetch_body"],
        ),
    ]
