from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cypher.ai.mock import MockProvider
from cypher.ai.ollama import OllamaProvider
from cypher.config.settings import SETTINGS
from cypher.core.challenge import ChallengeIntake
from cypher.core.investigation import InvestigationLoop
from cypher.core.state import InvestigationState, InvestigationStatus
from cypher.tools.registry import build_default_registry


def _build_provider(name: str):
    if name == "mock":
        return MockProvider()
    return OllamaProvider(model=SETTINGS.ollama_model, host=SETTINGS.ollama_host)


def cmd_solve(args: argparse.Namespace) -> int:
    if args.flag_only:
        # Flag-only mode must produce EXACTLY one line: the flag value, or
        # NOT_FOUND. No logs, warnings, or reasoning traces may leak onto
        # stdout/stderr in this mode — competition scripts may parse stdout
        # directly. This also guarantees nothing here can be mistaken for
        # an auto-submission payload: CYPHER never calls any submission
        # endpoint anywhere in this codebase, in any mode.
        logging.disable(logging.CRITICAL)

    intake = ChallengeIntake(SETTINGS.workspaces_root)
    if args.text:
        challenge = intake.ingest_text(args.text)
    elif getattr(args, "url", None):
        challenge = intake.ingest_url(args.url, description=args.description or "")
    elif args.challenge:
        challenge = intake.ingest_path(Path(args.challenge), description=args.description or "")
    else:
        print("Provide a challenge path, --text, or --url.", file=sys.stderr)
        return 2

    registry = build_default_registry()
    ai = _build_provider(args.provider or SETTINGS.provider)
    state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)

    loop = InvestigationLoop(
        ai=ai,
        registry=registry,
        challenge=challenge,
        state=state,
        max_iterations=args.max_iterations or SETTINGS.max_iterations,
        use_docker=SETTINGS.use_docker_sandbox,
        docker_image=SETTINGS.docker_image,
        sandbox_policy=SETTINGS.sandbox_policy,
    )
    _solve_start = time.monotonic()
    final_state = loop.run()
    total_runtime = time.monotonic() - _solve_start

    if args.flag_only:
        if final_state.status == InvestigationStatus.CONFIRMED and final_state.confirmed_flag:
            print(final_state.confirmed_flag["flag_value"])
        else:
            print("NOT_FOUND")
        return 0 if final_state.status == InvestigationStatus.CONFIRMED else 1

    _print_report(challenge, final_state, total_runtime)
    return 0 if final_state.status == InvestigationStatus.CONFIRMED else 1


def _print_report(challenge, state: InvestigationState, total_runtime: float | None = None) -> None:
    bar = "━" * 22
    print(f"{bar} CYPHER INVESTIGATION {bar}")
    print()
    print(f"Challenge: {challenge.challenge_id}  ({', '.join(f.original_name for f in challenge.files) or 'text-only'})")
    top = state.hypotheses.top()
    if top:
        print(f"Leading hypothesis: {top.statement}")
        print(f"  {top.id} — status: {top.status.value}, confidence: {top.priority:.2f}")
    print(f"Status: {state.status.value}   (escalation level {state.escalation_level}/8)")
    print()

    pursuable = [h for h in state.hypotheses.all() if h.status.value in ("active", "supported", "weakened")]
    other = [h for h in state.hypotheses.all() if h not in pursuable]
    print(f"Hypotheses considered: {len(state.hypotheses.all())} "
          f"({len(pursuable)} still pursuable, {len(other)} resolved)")
    for h in sorted(state.hypotheses.all(), key=lambda x: -x.priority)[:6]:
        print(f"  [{h.status.value:9s}] {h.id} conf={h.priority:.2f}  {h.statement[:70]}")
    print()

    print(f"Tool executions: {len(state.action_log)}   Evidence items: {len(state.evidence.all())}   "
          f"Discovered artifacts: {len(state.discovered_artifacts)}")
    if state.discovered_artifacts:
        for a in state.discovered_artifacts[:5]:
            print(f"  {a.relative_path}  (from {a.produced_by_tool}, depth {a.depth})")

    timing = state.timing_summary()
    runtime_str = f"{total_runtime:.1f}s total, " if total_runtime is not None else ""
    print(f"Timing: {runtime_str}{timing['ai_calls']} AI call(s) "
          f"(avg {timing['ai_time_avg_seconds']}s, total {timing['ai_time_total_seconds']}s), "
          f"tool time {timing['tool_time_total_seconds']}s")

    print()
    print("━" * 66)
    print("RESULT")
    print()
    if state.confirmed_flag:
        print("Status: CONFIRMED")
        print()
        print("Flag:")
        print(f"  {state.confirmed_flag['full_flag']}")
        print()
        chain_evidence = state.confirmed_flag.get("evidence_ids", [])
        if chain_evidence:
            ev = state.evidence.get(chain_evidence[0])
            chain_desc = f"{challenge.files[0].original_name if challenge.files else 'input'} -> {ev.source_tool}" if ev else ""
            method = state.confirmed_flag.get("method")
            if method:
                chain_desc += f" -> decoded ({method})"
            chain_desc += " -> verified candidate"
            print("Evidence chain:")
            print(f"  {chain_desc}")
        print()
        print(f"Reason: {state.confirmed_flag['reason']}")
    elif state.candidate_flags:
        print(f"Status: {state.status.value}")
        print(f"{len(state.candidate_flags)} unconfirmed/probable candidate(s) found but not confirmed.")
        print("(Full detail in state.json — nothing here should be submitted as-is.)")
    else:
        print(f"Status: {state.status.value}")
        print("No flag-shaped candidates were found across the investigation.")
    print("━" * 66)
    print()
    print(f"Full state (raw evidence, full hypothesis history) saved to: {challenge.workspace / 'state.json'}")


def cmd_inspect(args: argparse.Namespace) -> int:
    intake = ChallengeIntake(SETTINGS.workspaces_root)
    challenge = intake.ingest_path(Path(args.challenge), description=args.description or "")
    print(json.dumps(challenge.to_dict(), indent=2))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    # (name, status, level, detail) — status in {AVAILABLE, MISSING, BROKEN};
    # level in {REQUIRED, OPTIONAL} — a MISSING/BROKEN OPTIONAL check
    # reduces capability, not viability; REQUIRED failing blocks solving.
    checks: list[tuple[str, str, str, str]] = []

    checks.append(("Python", "AVAILABLE", "REQUIRED", sys.version.split()[0]))

    docker = shutil.which("docker")
    checks.append((
        "Docker CLI", "AVAILABLE" if docker else "MISSING", "REQUIRED",
        docker or "not found — sandbox-required tools will be BLOCKED_SANDBOX_REQUIRED in competition mode",
    ))

    docker_daemon_ok = False
    if docker:
        try:
            proc = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
            docker_daemon_ok = proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            docker_daemon_ok = False
        checks.append((
            "Docker daemon", "AVAILABLE" if docker_daemon_ok else "BROKEN", "REQUIRED",
            "responding" if docker_daemon_ok else "docker CLI present but daemon not responding — is Docker Desktop/dockerd running?",
        ))
        if docker_daemon_ok:
            try:
                proc = subprocess.run(
                    ["docker", "images", "-q", SETTINGS.docker_image],
                    capture_output=True, timeout=10, text=True,
                )
                image_exists = bool(proc.stdout.strip())
            except (subprocess.TimeoutExpired, OSError):
                image_exists = False
            checks.append((
                "Sandbox image", "AVAILABLE" if image_exists else "MISSING", "REQUIRED",
                SETTINGS.docker_image if image_exists else f"run: docker build -f sandbox/Dockerfile -t {SETTINGS.docker_image} .",
            ))
    else:
        checks.append(("Docker daemon", "MISSING", "REQUIRED", "Docker CLI not found, cannot check daemon"))
        checks.append(("Sandbox image", "MISSING", "REQUIRED", "Docker CLI not found, cannot check image"))

    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            proc = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
                capture_output=True, timeout=10, text=True,
            )
            gpu_info = proc.stdout.strip() or "nvidia-smi present but returned no GPU info"
            checks.append(("GPU/VRAM", "AVAILABLE", "OPTIONAL", gpu_info))
        except (subprocess.TimeoutExpired, OSError) as exc:
            checks.append(("GPU/VRAM", "BROKEN", "OPTIONAL", f"nvidia-smi failed: {exc}"))
    else:
        checks.append(("GPU/VRAM", "MISSING", "OPTIONAL", "nvidia-smi not found — CPU-only inference, or non-NVIDIA GPU (unchecked)"))

    wsl_marker = Path("/proc/version")
    is_wsl = False
    if wsl_marker.exists():
        try:
            is_wsl = "microsoft" in wsl_marker.read_text().lower()
        except OSError:
            pass
    checks.append(("WSL2/Linux env", "AVAILABLE", "OPTIONAL", "running inside WSL2" if is_wsl else "native Linux (or WSL marker not detected)"))

    ollama_bin = shutil.which("ollama")
    checks.append(("Ollama CLI", "AVAILABLE" if ollama_bin else "MISSING", "OPTIONAL", ollama_bin or "not on PATH (only needed to run `ollama pull`/`ollama serve` from this shell)"))

    provider = OllamaProvider(model=SETTINGS.ollama_model, host=SETTINGS.ollama_host)
    ok, msg = provider.health_check()
    checks.append(("Ollama server", "AVAILABLE" if ok else "BROKEN", "REQUIRED", msg))

    registry = build_default_registry()
    for tool in registry.list():
        status = "AVAILABLE" if tool.is_available() else "MISSING"
        level = "REQUIRED" if tool.category == "general" else "OPTIONAL"
        if not tool.is_available() and tool.required_python_packages and shutil.which(tool.executable):
            import importlib.util
            missing_pkgs = [p for p in tool.required_python_packages if importlib.util.find_spec(p) is None]
            detail = f"python package(s) not installed: {', '.join(missing_pkgs)} — pip install them for {tool.name}"
        else:
            detail = tool.executable if tool.is_available() else f"{tool.executable} not found — {tool.name} disabled, degrades gracefully"
        checks.append((f"tool:{tool.name}", status, level, detail))

    try:
        import shutil as _shutil
        total, used, free = _shutil.disk_usage(SETTINGS.workspaces_root if SETTINGS.workspaces_root.exists() else Path("."))
        free_gb = free / (1024 ** 3)
        checks.append((
            "Storage", "AVAILABLE" if free_gb > 2 else "BROKEN", "REQUIRED",
            f"{free_gb:.1f} GB free" + ("" if free_gb > 2 else " — dangerously low for archive extraction/model files"),
        ))
    except OSError as exc:
        checks.append(("Storage", "BROKEN", "REQUIRED", str(exc)))

    meminfo_path = Path("/proc/meminfo")
    if meminfo_path.exists():
        try:
            meminfo = meminfo_path.read_text()
            total_kb = int(next(l for l in meminfo.splitlines() if l.startswith("MemTotal:")).split()[1])
            total_gb = total_kb / (1024 ** 2)
            checks.append((
                "RAM", "AVAILABLE" if total_gb >= 8 else "BROKEN", "REQUIRED",
                f"{total_gb:.1f} GB total" + ("" if total_gb >= 8 else " — below the 16GB target hardware profile"),
            ))
        except (StopIteration, ValueError, OSError) as exc:
            checks.append(("RAM", "BROKEN", "OPTIONAL", f"could not parse /proc/meminfo: {exc}"))
    else:
        checks.append(("RAM", "MISSING", "OPTIONAL", "/proc/meminfo not available on this platform (non-Linux?) — check manually"))

    try:
        SETTINGS.workspaces_root.mkdir(parents=True, exist_ok=True)
        test_file = SETTINGS.workspaces_root / ".doctor_write_test"
        test_file.write_text("ok")
        test_file.unlink()
        checks.append(("Workspace writable", "AVAILABLE", "REQUIRED", str(SETTINGS.workspaces_root.resolve())))
    except OSError as exc:
        checks.append(("Workspace writable", "BROKEN", "REQUIRED", str(exc)))

    checks.append(("Sandbox policy", "AVAILABLE", "REQUIRED", SETTINGS.sandbox_policy))

    worst = "AVAILABLE"
    for _, status, level, _ in checks:
        if status == "BROKEN" and level == "REQUIRED":
            worst = "FAIL"
        elif status == "MISSING" and level == "REQUIRED" and worst != "FAIL":
            worst = "FAIL"

    for name, status, level, detail in checks:
        print(f"[{status:9s}] [{level:8s}] {name:24s} {detail}")
    print()
    tool_available = sum(1 for n, s, l, _ in checks if n.startswith("tool:") and s == "AVAILABLE")
    tool_total = sum(1 for n, *_ in checks if n.startswith("tool:"))
    print(f"Tools available: {tool_available}/{tool_total}")
    print(f"Overall: {'READY' if worst == 'AVAILABLE' else 'NOT READY — see REQUIRED failures above'}")
    return 0 if worst == "AVAILABLE" else 1


BENCHMARK_CHALLENGES = [
    # (name, builder(tmp_path) -> Challenge, expected_flag_value)
]


def _build_benchmark_challenges(tmp_path):
    """A handful of synthetic, self-contained challenges used as a sanity
    self-check, NOT a claim about real-world CTF difficulty. Real
    difficulty benchmarking requires actual public/authorized challenges
    tested against a live model — this only proves the plumbing works.
    """
    import base64
    import zipfile

    from cypher.core.challenge import ChallengeIntake

    challenges = []

    d = tmp_path / "b64"
    d.mkdir()
    p = d / "chal.txt"
    p.write_text(base64.b64encode(b"flag{benchmark_base64}").decode())
    challenges.append(("base64", ChallengeIntake(d / "ws"), p, "benchmark_base64"))

    d = tmp_path / "xor"
    d.mkdir()
    p = d / "chal.bin"
    p.write_bytes(bytes(b ^ 0x2A for b in b"flag{benchmark_xor}"))
    challenges.append(("xor", ChallengeIntake(d / "ws"), p, "benchmark_xor"))

    d = tmp_path / "archive"
    d.mkdir()
    inner = d / "secret.txt"
    inner.write_text(base64.b64encode(b"flag{benchmark_nested_archive}").decode())
    p = d / "chal.dat"
    with zipfile.ZipFile(p, "w") as zf:
        zf.write(inner, "secret.txt")
    challenges.append(("nested_archive", ChallengeIntake(d / "ws"), p, "benchmark_nested_archive"))

    return challenges


def cmd_benchmark(args: argparse.Namespace) -> int:
    import json
    import tempfile
    import time

    from cypher.ai.mock import MockProvider

    if args.dir:
        print(f"Running against challenges in {args.dir} — REAL CTF BENCHMARK mode.")
        print("Results here reflect actual investigation quality against real challenges,")
        print("using the configured AI provider (default: ollama). This is the number")
        print("that means something; the bundled synthetic set below does not.\n")
        return _run_directory_benchmark(Path(args.dir), args)

    print("Running CYPHER's bundled synthetic self-check — PLUMBING TEST, not a real")
    print("CTF benchmark. It proves the core loop still works end-to-end with a scripted")
    print("mock model; it says NOTHING about how well a live Ollama model reasons over")
    print("real challenges. For that, use: cypher benchmark --dir <challenges_folder>\n")

    registry = build_default_registry()
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, intake, path, expected in _build_benchmark_challenges(Path(tmp)):
            challenge = intake.ingest_path(path, description=f"benchmark: {name}")

            ai = MockProvider()
            ai.add_rule(lambda p: "Interpret this result" in p, lambda p: "{}")
            ai.add_rule(
                lambda p: '"hypotheses"' not in p and "hypothesis" not in p.lower() and False,
                lambda p: "{}",
            )
            # A scripted-but-generic responder: try auto_decode first (covers
            # base64/xor), then archive extraction, then the discovered file.
            ai.queue_response(json.dumps({"hypotheses": [
                {"statement": "Try common encodings and archive extraction.", "category": "crypto", "priority": 0.8}
            ]}))
            ai.queue_response(json.dumps({
                "tool": "auto_decode_common_encodings", "input": challenge.files[0].original_name,
                "extra_args": [], "reason": "try common encodings first",
            }))
            ai.queue_response(json.dumps({
                "tool": "safe_archive_extract", "input": challenge.files[0].original_name,
                "extra_args": [], "reason": "in case it's an archive",
            }))
            for _ in range(6):
                ai.queue_response(json.dumps({
                    "tool": "auto_decode_common_encodings", "input": "secret.txt", "extra_args": [],
                }))

            state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
            start = time.monotonic()
            loop = InvestigationLoop(
                ai=ai, registry=registry, challenge=challenge, state=state,
                max_iterations=8, sandbox_policy="development",
            )
            final_state = loop.run()
            duration = time.monotonic() - start

            solved = (
                final_state.status == InvestigationStatus.CONFIRMED
                and final_state.confirmed_flag is not None
                and final_state.confirmed_flag["flag_value"] == expected
            )
            false_positive = (
                final_state.status == InvestigationStatus.CONFIRMED
                and final_state.confirmed_flag is not None
                and final_state.confirmed_flag["flag_value"] != expected
            )
            results.append({
                "name": name, "solved": solved, "false_positive": false_positive,
                "status": final_state.status.value, "duration_seconds": round(duration, 2),
                "iterations": len(final_state.action_log),
                "hypotheses": len(final_state.hypotheses.all()),
            })

    solved_count = sum(1 for r in results if r["solved"])
    fp_count = sum(1 for r in results if r["false_positive"])
    for r in results:
        mark = "SOLVED" if r["solved"] else ("FALSE_POSITIVE" if r["false_positive"] else "NOT_SOLVED")
        print(f"[{mark:14s}] {r['name']:16s} status={r['status']:12s} "
              f"time={r['duration_seconds']}s tools={r['iterations']} hyps={r['hypotheses']}")
    print()
    print(f"Solved: {solved_count}/{len(results)}   False positives: {fp_count}")
    return 0 if fp_count == 0 and solved_count == len(results) else 1


def _run_directory_benchmark(directory: Path, args: argparse.Namespace) -> int:
    """Each immediate subdirectory of `directory` is treated as one
    challenge (files ingested from it; an optional description.txt sets
    the description). Uses the REAL configured provider by default, not
    MockProvider, since the whole point is measuring actual capability.
    """
    import time

    if not directory.is_dir():
        print(f"Not a directory: {directory}", file=sys.stderr)
        return 2

    registry = build_default_registry()
    ai_factory = lambda: _build_provider(args.provider or SETTINGS.provider)  # noqa: E731

    results = []
    subdirs = sorted(p for p in directory.iterdir() if p.is_dir())
    if not subdirs:
        print(f"No challenge subdirectories found under {directory}.")
        return 1

    for chal_dir in subdirs:
        desc_file = chal_dir / "description.txt"
        description = desc_file.read_text().strip() if desc_file.exists() else ""
        intake = ChallengeIntake(SETTINGS.workspaces_root)
        challenge = intake.ingest_path(chal_dir, description=description)

        state = InvestigationState.load_or_create(challenge.challenge_id, challenge.workspace)
        start = time.monotonic()
        loop = InvestigationLoop(
            ai=ai_factory(), registry=registry, challenge=challenge, state=state,
            max_iterations=args.max_iterations or SETTINGS.max_iterations,
            use_docker=SETTINGS.use_docker_sandbox, sandbox_policy=SETTINGS.sandbox_policy,
        )
        final_state = loop.run()
        duration = time.monotonic() - start

        results.append({
            "name": chal_dir.name,
            "status": final_state.status.value,
            "confirmed": final_state.confirmed_flag is not None,
            "duration_seconds": round(duration, 2),
            "tools_used": len(final_state.action_log),
            "hypotheses": len(final_state.hypotheses.all()),
            "escalation_level": final_state.escalation_level,
        })
        mark = "CONFIRMED" if final_state.confirmed_flag else final_state.status.value
        print(f"[{mark:14s}] {chal_dir.name:20s} time={duration:.1f}s tools={len(final_state.action_log)}")

    solved = sum(1 for r in results if r["confirmed"])
    print()
    print(f"Verified solve rate: {solved}/{len(results)}")
    print("(No claim is made about false positives beyond this build's flag verification")
    print(" guarantees — see PROVEN vs KNOWN LIMITATIONS in the project's final report.)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cypher")
    sub = parser.add_subparsers(dest="command", required=True)

    solve = sub.add_parser("solve", help="Investigate a challenge")
    solve.add_argument("challenge", nargs="?", help="Path to challenge file/directory")
    solve.add_argument("--text", help="Text-only challenge description")
    solve.add_argument("--url", help="Authorized web challenge target URL. CYPHER will never fetch outside this origin.")
    solve.add_argument("--description", help="Extra description to attach to a file/dir challenge")
    solve.add_argument("--flag-only", action="store_true", help="Print only the verified flag or NOT_FOUND")
    solve.add_argument("--max-iterations", type=int)
    solve.add_argument("--provider", choices=["ollama", "mock"])
    solve.set_defaults(func=cmd_solve)

    inspect = sub.add_parser("inspect", help="Ingest and show challenge metadata without investigating")
    inspect.add_argument("challenge")
    inspect.add_argument("--description")
    inspect.set_defaults(func=cmd_inspect)

    doctor = sub.add_parser("doctor", help="Check environment readiness")
    doctor.set_defaults(func=cmd_doctor)

    benchmark = sub.add_parser("benchmark", help="Run the bundled synthetic self-check, or --dir for real challenges")
    benchmark.add_argument("--dir", help="Directory of real challenge subfolders for a REAL benchmark (not the synthetic plumbing test)")
    benchmark.add_argument("--max-iterations", type=int)
    benchmark.add_argument("--provider", choices=["ollama", "mock"])
    benchmark.set_defaults(func=cmd_benchmark)

    version = sub.add_parser("version", help="Show version")
    version.set_defaults(func=lambda args: (print("cypher 0.1.0 (P0 vertical slice)"), 0)[1])

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
