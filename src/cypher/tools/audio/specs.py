from __future__ import annotations

from cypher.tools.schemas import SafetyClass, ToolSpec


def audio_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="audio_metadata",
            category="audio",
            description=(
                "Dump full container/stream metadata for an audio or video file "
                "(codec, sample rate, channels, duration, embedded tags/comments). "
                "Always run this first on any audio/media challenge file."
            ),
            executable="ffprobe",
            arg_template=["-v", "quiet", "-show_format", "-show_streams", "{input}"],
            input_types=["audio", "video"],
            timeout_seconds=20,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="audio_channel_split",
            category="audio",
            description=(
                "Split a stereo/multi-channel audio file into separate mono WAV files "
                "(left.wav, right.wav) inside the workspace. Hidden data or Morse/DTMF "
                "tones are sometimes isolated to a single channel."
            ),
            executable="ffmpeg",
            arg_template=[
                "-y", "-i", "{input}",
                "-filter_complex", "[0:a]channelsplit=channel_layout=stereo[left][right]",
                "-map", "[left]", "left.wav",
                "-map", "[right]", "right.wav",
            ],
            input_types=["audio"],
            timeout_seconds=30,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
        ToolSpec(
            name="audio_spectrogram",
            category="audio",
            description=(
                "Render a spectrogram PNG of the audio — the standard technique for "
                "challenges that hide an image or text visually in the frequency domain."
            ),
            executable="sox",
            arg_template=["{input}", "-n", "spectrogram", "-o", "spectrogram.png"],
            input_types=["audio"],
            timeout_seconds=30,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
        ToolSpec(
            name="audio_stat",
            category="audio",
            description=(
                "Print statistical analysis of an audio file (min/max amplitude, RMS, "
                "DC offset) — unusual values can indicate embedded data or clipping "
                "artifacts from data injection."
            ),
            executable="sox",
            arg_template=["{input}", "-n", "stat"],
            input_types=["audio"],
            timeout_seconds=20,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="audio_reverse",
            category="audio",
            description=(
                "Reverse an audio file in time — a classic hide-a-spoken-message-"
                "backwards trick. Output saved as reversed.wav for further listening/OCR."
            ),
            executable="sox",
            arg_template=["{input}", "reversed.wav", "reverse"],
            input_types=["audio"],
            timeout_seconds=20,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
        ToolSpec(
            name="audio_to_text_strings",
            category="audio",
            description=(
                "Extract printable strings from the raw audio file bytes — catches "
                "flags embedded as ID3/metadata tags or raw text appended to the file."
            ),
            executable="strings",
            arg_template=["-n", "4", "{input}"],
            input_types=["audio", "video"],
            timeout_seconds=15,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
    ]
