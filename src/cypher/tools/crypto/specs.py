from __future__ import annotations

from pathlib import Path

from cypher.tools.schemas import SafetyClass, ToolSpec

_SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"
_AUTO_DECODE_SCRIPT = str(_SCRIPT_DIR / "auto_decode.py")


def crypto_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="auto_decode_common_encodings",
            category="crypto",
            description=(
                "Deterministically try base64, hex, binary, all 25 Caesar/ROT-N shifts, "
                "and single-byte XOR (all 256 keys) against a file's contents, surfacing "
                "any decode that looks like English text or contains a flag-shaped "
                "substring. This is the strongest first move for any crypto challenge "
                "whose content isn't obviously already plaintext."
            ),
            executable="python3",
            arg_template=[_AUTO_DECODE_SCRIPT, "{input}"],
            input_types=["text", "binary"],
            timeout_seconds=30,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="base64_decode",
            category="crypto",
            description=(
                "Base64-decode a file's contents. Try this on any file/string that "
                "looks like base64 (charset A-Za-z0-9+/=, no spaces)."
            ),
            executable="base64",
            arg_template=["-d", "{input}"],
            input_types=["text"],
            timeout_seconds=10,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="hash_identify_sha256",
            category="crypto",
            description="Compute the SHA-256 hash of a file (for comparing against known hash-format flags).",
            executable="sha256sum",
            arg_template=["{input}"],
            input_types=["any"],
            timeout_seconds=10,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="hash_identify_md5",
            category="crypto",
            description="Compute the MD5 hash of a file.",
            executable="md5sum",
            arg_template=["{input}"],
            input_types=["any"],
            timeout_seconds=10,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="openssl_inspect",
            category="crypto",
            description=(
                "Inspect an X.509 certificate or key file's structure (RSA parameters, "
                "modulus, etc.) — useful for RSA-parameter-misuse challenges. "
                "Extra arg must be one of: x509, rsa, asn1parse."
            ),
            executable="openssl",
            arg_template=["{extra}", "-in", "{input}", "-text", "-noout"],
            allowed_extra_args=True,
            allowed_extra_arg_pattern=r"^(x509|rsa|asn1parse)$",
            input_types=["cert", "key", "binary"],
            timeout_seconds=15,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
    ]
