from __future__ import annotations

from cypher.tools.schemas import SafetyClass, ToolSpec


def stego_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="steghide_info",
            category="stego",
            description=(
                "Show whether a JPEG/BMP/WAV/AU file has steghide-embedded data and "
                "its size, WITHOUT a passphrase. Does not extract (extraction needs a "
                "passphrase this tool call does not accept)."
            ),
            executable="steghide",
            arg_template=["info", "{input}"],
            input_types=["image", "audio"],
            timeout_seconds=15,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="stegseek_crack",
            category="stego",
            description=(
                "Attempt to crack a steghide passphrase using the bundled wordlist and, "
                "on success, extract the hidden payload. Only useful if steghide_info "
                "confirmed embedded data is present."
            ),
            executable="stegseek",
            arg_template=["{input}", "/usr/share/wordlists/rockyou.txt"],
            input_types=["image", "audio"],
            timeout_seconds=120,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
        ToolSpec(
            name="zsteg_scan",
            category="stego",
            description=(
                "Scan a PNG/BMP for common LSB-steganography patterns across bit "
                "planes and channels. The standard first move for image-hides-a-flag "
                "challenges."
            ),
            executable="zsteg",
            arg_template=["-a", "{input}"],
            input_types=["image"],
            timeout_seconds=30,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
        ToolSpec(
            name="ocr_extract_text",
            category="stego",
            description="Run OCR on an image to pull out any rendered/printed text.",
            executable="tesseract",
            arg_template=["{input}", "stdout"],
            input_types=["image"],
            timeout_seconds=30,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="image_identify",
            category="stego",
            description=(
                "Show ImageMagick's detailed image identification: dimensions, "
                "color depth, embedded profiles, comment fields. Also flags "
                "dimension/size mismatches that can indicate hidden appended data."
            ),
            executable="identify",
            arg_template=["-verbose", "{input}"],
            input_types=["image"],
            timeout_seconds=15,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="image_channel_split",
            category="stego",
            description=(
                "Split an image into separate R/G/B channel grayscale images inside "
                "the workspace — a classic LSB-stego technique hides data in a single "
                "channel that's invisible when viewing all channels combined."
            ),
            executable="convert",
            arg_template=["{input}", "-channel", "RGB", "-separate", "channel_%d.png"],
            input_types=["image"],
            timeout_seconds=20,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
    ]
