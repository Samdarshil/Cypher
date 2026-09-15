# CYPHER — P0 Vertical Slice

Local-first CTF intelligence & analysis system. This is the working P0
core: **Challenge → AIProvider → Hypothesis → Tool Selection → Controlled
Execution → Evidence → Flag Extraction → Verification → Result**, built
per the CYPHER master spec and audited against `verialabs/ctf-agent`.

## What actually runs right now

```
uv sync  # or: pip install -e . --break-system-packages
export CYPHER_OLLAMA_MODEL=qwen3:4b   # or qwen3:8b if VRAM allows
python -m cypher.cli.main doctor
python -m cypher.cli.main solve path/to/challenge.zip
python -m cypher.cli.main solve path/to/challenge.zip --flag-only
python -m cypher.cli.main inspect path/to/challenge.zip
```

Without `pyproject.toml` install, run with `PYTHONPATH=src` instead.

Tests (stdlib-only shim included since this environment has no network
access to install real pytest — swap in real `pytest` on your machine,
the test files are pytest-compatible as written):

```
python -m pytest tests/            # on your machine
python tests/_pytest_shim.py       # offline fallback used to validate this build
```

All 14 tests pass, including a full end-to-end run of the investigation
loop against a synthetic challenge (mocked AI, real coreutils tool
execution, real flag verification).

## Audit summary — `verialabs/ctf-agent`

| Component | Verdict |
|---|---|
| Docker sandbox tool arsenal (radare2, pwntools, RsaCtfTool, volatility3, steghide, zsteg, angr, ffmpeg, sox, ...) | **REUSE** — carried into `sandbox/Dockerfile` |
| Cloud-model coordinator (Claude SDK / Codex CLI, N-model racing) | **REPLACE** — CYPHER uses local Ollama via `AIProvider`, one model at a time, sized for 6GB VRAM |
| CTFd poller / "auto-spawn" (autonomous challenge selection) | **REMOVED** — violates human-in-the-loop requirement, not present in CYPHER at all |
| `pull_challenges.py` (CTFd fetch) | **REFACTOR candidate** — keep only as an on-demand, human-triggered single-challenge fetch; not built yet (not P0) |
| Auto flag submission | **N/A in CYPHER** — the system only ever reaches `CONFIRMED` and prints it; nothing submits anywhere |

## What's implemented (P0)

- `ai/` — `AIProvider` abstract base, `OllamaProvider` (stdlib `urllib`,
  zero required deps), `MockProvider` for tests.
- `core/challenge.py` — isolated per-challenge workspace, sha256 hashing,
  path-traversal-safe archive extraction with decompression-bomb limits.
- `core/hypotheses.py` — mutable, ranked, multi-hypothesis board.
- `evidence/models.py` — append-only evidence store; every entry is
  backed by a real file on disk so flags can be traced to raw tool output.
- `tools/registry.py` + `tools/schemas.py` — allow-listed tool
  declarations (currently: `file`, `strings`, `grep`, `xxd`). Specialist
  categories (forensics/stego/crypto/reverse/pwn/web/osint) register the
  same way — this is the next thing to extend.
- `tools/executor.py` — the only place a subprocess is spawned. Argv-list
  execution (never shell=True), path-traversal checks, arg allow-listing,
  timeouts, POSIX resource limits (CPU/memory/no-core-dumps), stripped
  environment.
- `flags/extractor.py` + `flags/verifier.py` — extraction is generous,
  verification is conservative: a candidate is only `CONFIRMED` if it's
  found **verbatim in stored raw tool output**, not merely asserted by
  the model. This is the anti-false-positive guarantee the spec requires
  given negative marking.
- `core/investigation.py` — the OBSERVE→HYPOTHESIZE→PLAN→SELECT→EXECUTE→
  INTERPRET→VERIFY loop, with failed-strategy memory and escalation.
- `core/state.py` — persistent, resumable investigation state
  (`state.json` per challenge workspace).
- `cli/main.py` — `solve`, `inspect`, `doctor`, `version`.

## Explicit non-goals honored

- No automatic flag submission anywhere in the code.
- No autonomous CTFd polling / challenge selection — the human always
  supplies one challenge per `solve` invocation.
- Challenge content (filenames, descriptions, tool output) is only ever
  passed to the AI provider as labeled data inside a system-policy
  preamble that instructs the model to never treat it as instructions.
- The LLM cannot execute arbitrary commands — it can only name a
  registered tool + input file, which the executor independently validates.

## Honest limitations of this build

- **Only 4 general-purpose tools are registered** (`file`, `strings`,
  `grep`, `xxd`). The forensics/stego/crypto/reverse/pwn/web/osint
  specialist tool sets from the spec are not wired in yet — do that next
  by adding `ToolSpec`s in `tools/forensics/`, `tools/stego/`, etc. and
  registering them in `build_default_registry()`. The Dockerfile already
  installs most of the binaries; the Python-side registration is the gap.
- **No Docker-based sandbox isolation yet** — the executor enforces
  timeouts/resource limits/path checks directly on the host process.
  `sandbox/Dockerfile` exists but the executor doesn't shell out to
  `docker run` yet. For untrusted binaries (pwn/rev categories especially)
  wire that up before running this against real malicious challenge
  binaries.
- **No benchmarking harness yet** (spec sections 28-30) — not P0.
- **Hypothesis interpretation is heuristic, not LLM-driven** for the
  "update priority based on evidence" step — it uses simple rules
  (found candidate → boost, tool failed → penalize) rather than asking
  the model to reason about it. This was a deliberate scope cut to get
  the vertical slice working and testable; upgrading it to ask the model
  "does this evidence support or contradict H3?" is a natural next step.
- **This environment had no network access**, so `OllamaProvider` is
  implemented but untested against a live Ollama server — test it on
  your machine with `ollama serve` running and `ollama pull qwen3:4b`
  first (that's what `cypher doctor` checks for).

## Next steps, in priority order

1. Run `cypher doctor` on your actual Windows/WSL2 box, fix any FAIL/WARN.
2. Pull a model (`ollama pull qwen3:4b`), run `cypher solve` against a
   real easy public CTF challenge, read `state.json` to see the full
   reasoning trace.
3. Add specialist tools (start with `exiftool`, `binwalk`, `zsteg` — high
   value for forensics/stego categories) to the registry.
4. Wire the executor to optionally run tools inside `sandbox/Dockerfile`
   for anything untrusted (pwn/rev binaries especially).
5. Add the benchmarking harness once the tool arsenal is broader.
