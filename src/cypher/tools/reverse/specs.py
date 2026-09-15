from __future__ import annotations

from pathlib import Path

from cypher.tools.schemas import SafetyClass, ToolSpec

_SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"
_PATTERN_SCAN_SCRIPT = str(_SCRIPT_DIR / "pattern_scan.py")


def reverse_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="suspicious_pattern_scan",
            category="reverse",
            description=(
                "Heuristic scan for comparison functions (strcmp/memcmp/etc), "
                "flag-shaped strings, and base64/hex-looking blobs in a binary's "
                "printable strings. This is a triage step (tells you WHERE to look), "
                "not real disassembly — follow up with objdump_disasm or gdb for that. "
                "Good early move on any reverse/pwn binary."
            ),
            executable="python3",
            arg_template=[_PATTERN_SCAN_SCRIPT, "{input}"],
            input_types=["binary"],
            timeout_seconds=20,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
            common_followups=["objdump_disasm", "radare2_info"],
        ),
        ToolSpec(
            name="elf_headers",
            category="reverse",
            description=(
                "Show ELF headers, sections, and program headers for a binary "
                "(architecture, entry point, mitigations like NX/PIE/RELRO/canary). "
                "Always run this first on any unknown binary."
            ),
            executable="readelf",
            arg_template=["-a", "{input}"],
            input_types=["binary"],
            timeout_seconds=15,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="objdump_disasm",
            category="reverse",
            description="Disassemble a binary's executable sections (static disassembly, no execution).",
            executable="objdump",
            arg_template=["-d", "-M", "intel", "{input}"],
            input_types=["binary"],
            timeout_seconds=30,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="symbol_table",
            category="reverse",
            description="List a binary's symbol table (function/variable names) — useful for spotting suspicious function names.",
            executable="nm",
            arg_template=["-C", "{input}"],
            input_types=["binary"],
            timeout_seconds=15,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="radare2_info",
            category="reverse",
            description=(
                "Run radare2's automatic analysis and print a summary (functions found, "
                "strings, imports/exports). Static analysis only, no execution."
            ),
            executable="r2",
            arg_template=["-q", "-c", "aaa; afl; iz", "{input}"],
            input_types=["binary"],
            timeout_seconds=60,
            requires_sandbox=True,
            safety=SafetyClass.MODERATE,
        ),
        ToolSpec(
            name="checksec_mitigations",
            category="reverse",
            description=(
                "Report binary security mitigations: NX, PIE, stack canary, RELRO, "
                "Fortify. The standard first step for any pwn challenge — determines "
                "which exploit techniques are even viable before anything else."
            ),
            executable="checksec",
            arg_template=["--file={input}"],
            input_types=["binary"],
            timeout_seconds=15,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
            common_followups=["objdump_disasm", "rop_gadget_search"],
        ),
        ToolSpec(
            name="rop_gadget_search",
            category="reverse",
            description=(
                "Search a binary for ROP gadgets (static disassembly search, does NOT "
                "execute the binary). Useful once checksec shows NX is enabled, ruling "
                "out plain shellcode injection."
            ),
            executable="ROPgadget",
            arg_template=["--binary", "{input}"],
            input_types=["binary"],
            timeout_seconds=30,
            requires_sandbox=False,
            safety=SafetyClass.SAFE,
        ),
        ToolSpec(
            name="gdb_batch_run",
            category="reverse",
            description=(
                "DYNAMIC execution: run the target binary under gdb in batch mode to "
                "observe crash behavior / offsets. This actually EXECUTES the challenge "
                "binary, which may be malicious — always requires sandbox isolation, "
                "never runs on bare host."
            ),
            executable="gdb",
            arg_template=["-q", "--batch", "-ex", "run", "-ex", "bt", "{input}"],
            input_types=["binary"],
            timeout_seconds=20,
            requires_sandbox=True,
            requires_network=False,
            safety=SafetyClass.ELEVATED,
            max_cpu_seconds=10,
            max_memory_bytes=256 * 1024 * 1024,  # tighter cap: this actually
            # executes an untrusted challenge binary, so a misbehaving one
            # gets choked fast even inside its own timeout window
        ),
        ToolSpec(
            name="pwntools_probe",
            category="reverse",
            description=(
                "DYNAMIC execution: run a minimal pwntools probe script against the "
                "target binary (checks basic I/O behavior). Actually executes the "
                "binary — always requires sandbox isolation."
            ),
            executable="python3",
            arg_template=["-c", "import pwn,sys; p=pwn.process(sys.argv[1]); p.send(b'A'*64); print(p.recvall(timeout=2))", "{input}"],
            input_types=["binary"],
            timeout_seconds=15,
            requires_sandbox=True,
            requires_network=False,
            safety=SafetyClass.ELEVATED,
            max_cpu_seconds=10,
            max_memory_bytes=256 * 1024 * 1024,
            required_python_packages=["pwn"],
        ),
    ]
