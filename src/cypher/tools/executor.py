"""Controlled tool executor.

Hard rule: the LLM never gets raw shell access. This module is the only
place a subprocess is spawned, and every call goes through:
  1. tool must be registered
  2. input file must resolve inside the challenge workspace (no traversal)
  3. extra args must match the tool's allow-listed pattern
  4. execution is argv-list based (never shell=True), with a timeout and
     (on POSIX) CPU/memory resource limits, and a stripped environment.

Sandbox modes: any ToolSpec with requires_sandbox=True is routed through
`docker run --network=none` (isolated filesystem via bind mount, no host
secrets, capped CPU/memory/pids) when Docker is available and enabled.
If Docker isn't available, execution falls back to the host process with
the same resource limits/timeout as always, and the result is flagged
with sandbox_mode="host-fallback" so the caller/report can tell the
difference — this is an explicit degrade, never a silent one.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .registry import ToolRegistry
from .schemas import ToolSpec

try:
    import resource  # POSIX only

    _HAS_RESOURCE = True
except ImportError:  # Windows fallback — rely on timeout only
    _HAS_RESOURCE = False


DEFAULT_MAX_CPU_SECONDS = 30
DEFAULT_MAX_MEMORY_BYTES = 1024 * 1024 * 1024  # 1GB
DEFAULT_DOCKER_IMAGE = "cypher-sandbox"
DEFAULT_DOCKER_MEMORY = "1g"
DEFAULT_DOCKER_PIDS_LIMIT = "64"


class ToolValidationError(RuntimeError):
    pass


@dataclass
class ToolResult:
    tool_name: str
    argv: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    truncated: bool
    sandbox_mode: str = "host"  # "docker" | "host" | "host-fallback"

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "argv": self.argv,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": self.duration_seconds,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "sandbox_mode": self.sandbox_mode,
        }


def _limit_resources(max_cpu_seconds: int, max_memory_bytes: int):
    """Returns a preexec_fn for subprocess.Popen on POSIX, or None."""
    if not _HAS_RESOURCE:
        return None

    def _setter():
        resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_seconds, max_cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (max_memory_bytes, max_memory_bytes))
        # Prevent core dumps and limit number of child processes.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
        except (ValueError, OSError):
            pass  # some platforms restrict changing NPROC; non-fatal

    return _setter


class ToolExecutor:
    def __init__(
        self,
        registry: ToolRegistry,
        workspace: Path,
        use_docker: bool = False,
        docker_image: str = DEFAULT_DOCKER_IMAGE,
        sandbox_policy: str = "competition",  # "competition" | "development"
        authorized_urls: list[str] | None = None,
    ) -> None:
        self.registry = registry
        self.workspace = Path(workspace).resolve()
        self.use_docker = use_docker
        self.docker_image = docker_image
        if sandbox_policy not in ("competition", "development"):
            raise ValueError("sandbox_policy must be 'competition' or 'development'")
        self.sandbox_policy = sandbox_policy
        self.authorized_urls = authorized_urls or []

    def docker_available(self) -> bool:
        return shutil.which("docker") is not None

    def _resolve_input(self, input_path: str) -> Path:
        candidate = (self.workspace / input_path).resolve() if not Path(input_path).is_absolute() else Path(input_path).resolve()
        if not str(candidate).startswith(str(self.workspace)):
            raise ToolValidationError(
                f"Input path {input_path!r} resolves outside the challenge workspace — refused."
            )
        if not candidate.exists():
            raise ToolValidationError(f"Input file does not exist: {candidate}")
        return candidate

    def _build_native_argv(self, spec: ToolSpec, resolved_input: Path, extra_args: list[str]) -> list[str]:
        argv = [spec.executable]
        for part in spec.arg_template:
            if part == "{input}":
                argv.append(str(resolved_input))
            elif part == "{extra}":
                argv.extend(extra_args)
            else:
                argv.append(part)
        return argv

    def _build_docker_argv(self, spec: ToolSpec, resolved_input: Path, extra_args: list[str]) -> list[str]:
        # Inside the container, the whole workspace is mounted at /work, so
        # the tool sees the same relative path it would on the host.
        rel_input = resolved_input.relative_to(self.workspace)
        docker_argv = [
            "docker", "run", "--rm",
            "--network", "none" if not spec.requires_network else "bridge",
            "--memory", DEFAULT_DOCKER_MEMORY,
            "--cpus", "1",
            "--pids-limit", DEFAULT_DOCKER_PIDS_LIMIT,
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            "-v", f"{self.workspace}:/work",
            "--workdir", "/work",
            self.docker_image,
        ]
        tool_argv = [spec.executable]
        for part in spec.arg_template:
            if part == "{input}":
                tool_argv.append(str(rel_input))
            elif part == "{extra}":
                tool_argv.extend(extra_args)
            else:
                tool_argv.append(part)
        return docker_argv + tool_argv

    def _execute_web_tool(self, spec: ToolSpec, input_path: str) -> ToolResult:
        """URL-input tools never spawn a subprocess and never touch the
        workspace filesystem for their input — they go through the
        origin-restricted fetcher instead. The safety property (never
        fetch outside the operator-authorized origin) is enforced inside
        cypher.tools.web.fetcher, not here; this is just dispatch.
        """
        from cypher.tools.web.fetcher import WebPolicyError, derive_path, fetch

        start = time.monotonic()
        try:
            if spec.name == "web_fetch_headers":
                result = fetch(input_path, self.authorized_urls, headers_only=True)
                stdout = f"HTTP {result.status} {result.final_url}\n" + "\n".join(
                    f"{k}: {v}" for k, v in result.headers.items()
                )
            elif spec.name == "web_fetch_body":
                result = fetch(input_path, self.authorized_urls)
                stdout = result.to_text()
            elif spec.name == "web_fetch_robots":
                url = derive_path(input_path, "/robots.txt")
                result = fetch(url, self.authorized_urls)
                stdout = result.to_text()
            elif spec.name == "web_fetch_sitemap":
                url = derive_path(input_path, "/sitemap.xml")
                result = fetch(url, self.authorized_urls)
                stdout = result.to_text()
            else:
                raise ToolValidationError(f"Unrecognized web tool: {spec.name}")
        except WebPolicyError as exc:
            # A policy refusal is not a crash and not a silent bypass —
            # it's informative failure feedback, exactly like
            # BLOCKED_SANDBOX_REQUIRED.
            return ToolResult(
                tool_name=spec.name, argv=[], exit_code=None, stdout="",
                stderr=f"WEB_POLICY_BLOCKED: {exc}", duration_seconds=time.monotonic() - start,
                timed_out=False, truncated=False, sandbox_mode="blocked_web_policy",
            )
        except OSError as exc:
            # Network errors (DNS failure, connection refused, timeout) are
            # meaningful evidence, not a validation error -- surface them
            # as a failed-but-informative tool result.
            return ToolResult(
                tool_name=spec.name, argv=[], exit_code=1, stdout="",
                stderr=f"Fetch failed: {exc}", duration_seconds=time.monotonic() - start,
                timed_out=False, truncated=False, sandbox_mode="host",
            )

        truncated = len(stdout.encode("utf-8", errors="replace")) > spec.max_output_bytes
        if truncated:
            stdout = stdout[: spec.max_output_bytes]
        return ToolResult(
            tool_name=spec.name, argv=[f"__web__:{input_path}"], exit_code=0, stdout=stdout,
            stderr="", duration_seconds=time.monotonic() - start, timed_out=False,
            truncated=truncated, sandbox_mode="host",
        )

    def execute(
        self,
        tool_name: str,
        input_path: str,
        extra_args: list[str] | None = None,
    ) -> ToolResult:
        extra_args = extra_args or []
        spec: ToolSpec | None = self.registry.get(tool_name)
        if spec is None:
            raise ToolValidationError(f"Unknown tool: {tool_name!r}. Not in registry.")
        if not spec.is_available():
            raise ToolValidationError(f"Tool '{tool_name}' is registered but not installed on this system.")

        ok, msg = spec.validate_extra_args(extra_args)
        if not ok:
            raise ToolValidationError(msg)

        if spec.url_input:
            return self._execute_web_tool(spec, input_path)

        resolved_input = self._resolve_input(input_path)

        want_docker = self.use_docker and spec.requires_sandbox
        sandbox_mode = "host"
        if want_docker and self.docker_available():
            argv = self._build_docker_argv(spec, resolved_input, extra_args)
            sandbox_mode = "docker"
            timeout_budget = spec.timeout_seconds + 10  # small headroom for container startup
        elif spec.requires_sandbox and not self.docker_available() and self.sandbox_policy == "competition":
            # Competition mode is safety-first: a sandbox-required tool with
            # no sandbox available is a BLOCK, never a silent host run.
            return ToolResult(
                tool_name=tool_name,
                argv=[],
                exit_code=None,
                stdout="",
                stderr=(
                    "BLOCKED_SANDBOX_REQUIRED: this tool requires Docker-based "
                    "isolation and Docker is not available. Refusing to run it "
                    "on the bare host in competition mode. Install/start Docker "
                    "(see sandbox/Dockerfile) or switch to development mode."
                ),
                duration_seconds=0.0,
                timed_out=False,
                truncated=False,
                sandbox_mode="blocked_sandbox_required",
            )
        else:
            argv = self._build_native_argv(spec, resolved_input, extra_args)
            sandbox_mode = "host-fallback" if want_docker else "host"
            timeout_budget = spec.timeout_seconds

        preexec = None if sandbox_mode == "docker" else _limit_resources(
            spec.max_cpu_seconds or spec.timeout_seconds,
            spec.max_memory_bytes or DEFAULT_MAX_MEMORY_BYTES,
        )
        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                argv,
                cwd=self.workspace,
                capture_output=True,
                timeout=timeout_budget,
                env={"PATH": "/usr/bin:/bin:/usr/local/bin"},  # stripped env, no host secrets
                preexec_fn=preexec,
                stdin=subprocess.DEVNULL,  # a misconfigured/argument-starved
                # tool (e.g. grep with no pattern arg, which then reads its
                # "pattern" from the input path and waits on stdin for a
                # file) must never be able to hang waiting for interactive
                # input — it gets immediate EOF and fails fast instead.
            )
            stdout_bytes, stderr_bytes, exit_code = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout_bytes = exc.stdout or b""
            stderr_bytes = exc.stderr or b""
            exit_code = None

        duration = time.monotonic() - start

        truncated = False
        if len(stdout_bytes) > spec.max_output_bytes:
            stdout_bytes = stdout_bytes[: spec.max_output_bytes]
            truncated = True

        return ToolResult(
            tool_name=tool_name,
            argv=argv,
            exit_code=exit_code,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_seconds=duration,
            timed_out=timed_out,
            truncated=truncated,
            sandbox_mode=sandbox_mode,
        )
