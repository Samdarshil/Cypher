# CYPHER — Cyber Intelligence & Analysis System

**A local-first, human-in-the-loop AI investigation engine for authorized CTF challenges.**

CYPHER takes one challenge at a time from a human operator, autonomously investigates it using a local LLM (via [Ollama](https://ollama.com)) paired with a registry of deterministic security tools, and reports a flag only when it can prove — from real tool output, not model confidence — that the flag is correct. The human always decides what to submit and where.

```
cypher solve challenge.zip
```

---

## Table of contents

- [Design philosophy](#design-philosophy)
- [What CYPHER will and won't do](#what-cypher-will-and-wont-do)
- [How an investigation works](#how-an-investigation-works)
- [Quickstart](#quickstart)
- [Installation](#installation)
- [CLI reference](#cli-reference)
- [Tool registry](#tool-registry)
- [Security model](#security-model)
- [Flag verification](#flag-verification)
- [Artifact-aware recursion](#artifact-aware-recursion)
- [Evidence, state, and resumability](#evidence-state-and-resumability)
- [Configuration](#configuration)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Benchmarking](#benchmarking)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [License and authorized use](#license-and-authorized-use)

---

## Design philosophy

**Evidence beats model confidence.** CYPHER never treats an LLM's assertion — a plausible-looking string, a confident claim, a hypothesis — as a confirmed flag. A flag is only `CONFIRMED` when it can be traced back to something a real, deterministic tool actually printed, which is stored on disk and independently re-checked. This matters because most CTF scoring uses negative marking: a wrong submission costs more than a slow one.

**The LLM reasons; it does not execute.** CYPHER is not `User → LLM → Answer`. It is:

```
Challenge → Observe → Hypothesize → Plan → Select Tool → Execute (sandboxed)
    → Collect Evidence → Interpret → Update Hypotheses → Discover Artifacts
    → Repeat → Verify → CONFIRMED flag
```

The model can only select from a fixed, pre-registered list of tools with validated arguments. It can never construct or run an arbitrary shell command.

**The human stays in control.** CYPHER investigates one operator-supplied challenge at a time. It never polls a CTF platform, never picks its own targets, and never submits a flag anywhere — it prints a verified answer and stops. Submission is always a manual, human decision.

---

## What CYPHER will and won't do

**It will:**
- Ingest a file, directory, text description, or an explicitly authorized web URL as a single challenge.
- Generate and rank competing hypotheses about what the challenge needs, and revise them as evidence comes in.
- Select and run deterministic tools (forensics, stego, audio, crypto, reverse engineering, web, OSINT) safely and with resource limits.
- Recursively investigate new files that tools produce (e.g. an archive tool unpacking a hidden payload), with cycle and depth protection.
- Refuse to call a result `CONFIRMED` unless it's backed by real, reproducible tool output.
- Run fully offline against local files once a model is pulled — no cloud API dependency by default.

**It will not:**
- Submit a flag to any platform automatically.
- Select its own challenges or poll a CTF scoreboard.
- Run a tool that requires sandbox isolation on the bare host when Docker isn't available in competition mode — it fails closed (`BLOCKED_SANDBOX_REQUIRED`) instead.
- Fetch a URL outside the one origin an operator explicitly authorized for a web challenge, regardless of what the model or the challenge content suggests.
- Attack, scan, or interact with any target the operator didn't explicitly hand it.
- Do real exploit development. Pwn support is static triage plus sandbox-gated dynamic *probing* stubs, not an automatic exploit generator.

---

## How an investigation works

1. **Intake** — the challenge (file/dir/text/URL) is copied into an isolated per-challenge workspace. Every file is hashed, MIME-typed, and archives are safely unpacked (path-traversal and decompression-bomb protected).
2. **Observe & hypothesize** — the model is shown the challenge description, file list, and the tool registry, and proposes 1–4 ranked hypotheses (e.g. *"data hidden in image metadata"*, *"single-byte XOR encoding"*).
3. **Plan & select** — for the top-ranked hypothesis, the model picks one registered tool and one input file. If it picks badly (invalid tool, already-tried combination, malformed response), CYPHER falls back to rotating through untried (tool, file) pairs automatically — the investigation never stalls because of a bad model response.
4. **Execute** — the tool runs through a single, audited executor: argv-list execution (never a shell string), path-traversal checks, per-tool timeout and CPU/memory limits, and — for anything flagged as needing isolation — Docker sandboxing, or an explicit refusal if Docker isn't available in competition mode.
5. **Evidence & interpretation** — the raw output is stored on disk; a summary and an AI-generated interpretation ("what did this tell us, does it support or contradict the hypothesis") are attached, but flag detection *only* ever reads the raw tool output, never the interpretation text.
6. **Artifact discovery** — if the tool created new files, each one is hashed, checked against everything seen so far (cycle prevention), and — if genuinely new — becomes a fresh investigation target with its own follow-up hypothesis, up to a bounded recursion depth.
7. **Hypothesis update** — supporting evidence raises a hypothesis's priority and status (`ACTIVE → SUPPORTED`); repeated failure lowers it (`→ WEAKENED → REJECTED`) or marks it `EXHAUSTED` once every relevant tool/file combination has been tried.
8. **Repeat** — the loop continues, escalating investigation depth (levels 1–8) as hypotheses run out, until a flag is confirmed or the investigation is genuinely exhausted.
9. **Verify** — any flag-shaped string found in real tool output is checked: does it appear verbatim in stored evidence, is that evidence relevant enough, is it corroborated by more than one tool? Only then is it `CONFIRMED`.

---

## Quickstart

```bash
# 1. Install Ollama and pull a model sized for your GPU
ollama pull qwen3:4b        # ~6GB VRAM class
# ollama pull qwen3:8b      # if you have more headroom — benchmark both

# 2. Build the sandbox image (needed for anything flagged requires_sandbox)
docker build -f sandbox/Dockerfile -t cypher-sandbox .

# 3. Check your environment
python -m cypher.cli.main doctor

# 4. Investigate a challenge
python -m cypher.cli.main solve path/to/challenge.zip

# 5. Get just the flag, for scripting/quick checks
python -m cypher.cli.main solve path/to/challenge.zip --flag-only
```

If you've installed the package (`pip install -e .`), replace `python -m cypher.cli.main` with `cypher` everywhere above.

---

## Installation

**Requirements**
- Python 3.10+
- [Ollama](https://ollama.com) installed and reachable (default `http://localhost:11434`)
- Docker (strongly recommended — required for `requires_sandbox` tools in competition mode)
- ~300GB free disk recommended for models + tool installs; CYPHER itself is lightweight

**Install**
```bash
git clone <this-repo>
cd cypher
pip install -e .                    # installs the `cypher` command
# or, without installing:
PYTHONPATH=src python -m cypher.cli.main <command>
```

**Set up the model**
```bash
ollama serve                        # if not already running as a service
ollama pull qwen3:4b
```
CYPHER's architecture is model-agnostic (see [`ai/base.py`](src/cypher/ai/base.py)) — swap models via `CYPHER_OLLAMA_MODEL` without touching code. Benchmark `qwen3:4b` against `qwen3:8b` (or others) on your own hardware; don't assume the bigger model is the better default on a 6GB-class GPU.

**Build the sandbox image** (see [Security model](#security-model) for why this matters)
```bash
docker build -f sandbox/Dockerfile -t cypher-sandbox .
```
The Dockerfile installs the tool arsenal (`exiftool`, `binwalk`, `steghide`, `zsteg`, `radare2`, `gdb`, `pwntools`, `ROPgadget`, `ffmpeg`, `sox`, and more) with no silently-swallowed install failures — if a package fails to install, the build fails loudly.

**Verify everything**
```bash
cypher doctor
```
This reports `AVAILABLE` / `MISSING` / `BROKEN` for Python, Docker (CLI *and* daemon), the sandbox image, Ollama (server *and* the configured model), GPU/VRAM (best-effort via `nvidia-smi`), RAM, disk space, and every registered tool — each tagged `REQUIRED` or `OPTIONAL` so you know what actually blocks solving versus what just reduces coverage.

---

## CLI reference

| Command | Description |
|---|---|
| `cypher solve <path>` | Investigate a local file, directory, or archive. |
| `cypher solve --text "..."` | Investigate a text-only challenge (description/hints only, no files). |
| `cypher solve --url <authorized_url>` | Investigate a web challenge. CYPHER will only ever fetch this origin. |
| `cypher solve <path> --flag-only` | Print **only** the flag's inner content (or `NOT_FOUND`) — nothing else, on stdout or stderr. Exit code 0 if confirmed, 1 otherwise. |
| `cypher solve <path> --max-iterations N` | Override the iteration budget (default 15; raise this if using an unproven/weak model). |
| `cypher solve <path> --provider {ollama,mock}` | Force a specific AI backend. |
| `cypher inspect <path>` | Ingest and print challenge metadata (files, hashes, MIME types) without investigating. |
| `cypher doctor` | Full environment readiness report. |
| `cypher benchmark` | Run the bundled synthetic self-check (plumbing test, *not* a difficulty benchmark). |
| `cypher benchmark --dir <folder>` | Run against real challenges (one subfolder per challenge, optional `description.txt`) using the real configured AI provider — this is the number that actually means something. |
| `cypher version` | Print the version string. |

`--flag-only` is strict by contract: for a challenge with full flag `JNUCTF{abc123}`, it prints exactly `abc123` and nothing else. No progress logs, no reasoning, no disclaimers — verified with byte-exact output tests.

---

## Tool registry

Every tool CYPHER can call is declared once, centrally, with explicit metadata (category, description, input/output types, timeout, CPU/memory limits, sandbox and network requirements, safety class, and common follow-up tools). The model can only ever select from this list — there is no path from an LLM response to an arbitrary shell command.

| Category | Count | Examples |
|---|---|---|
| General | 5 | `file`, `strings`, `grep`/`ripgrep`, `xxd` |
| Forensics | 5 | `exiftool`, `binwalk` (scan + extract), `foremost`, safe archive extraction |
| Steganography | 6 | `steghide`, `stegseek`, `zsteg`, ImageMagick channel-split, OCR |
| Audio | 6 | `ffprobe` metadata, channel split, spectrogram, waveform stats, reversal |
| Crypto | 5 | auto-decoder (base64/hex/binary/ROT-N/single-byte XOR), hash tools, `openssl` |
| Reverse | 9 | `readelf`, `objdump`, `nm`, `radare2`, `checksec`, `ROPgadget`, a heuristic suspicious-pattern scanner, plus sandbox-gated dynamic stubs (`gdb`, `pwntools`) |
| Web | 4 | origin-restricted header/body/robots.txt/sitemap fetchers |
| OSINT | 1 | deterministic entity extraction (emails, domains, IPs, handles, dates) with cross-evidence corroboration |

**41 tools total.** Every one degrades gracefully if its underlying binary isn't installed (`cypher doctor` tells you exactly what's missing) rather than crashing the investigation.

---

## Security model

- **No unrestricted shell access, ever.** The tool executor is the only place a subprocess is spawned, using argv lists (never a shell string), a stripped environment, and validated arguments against a per-tool allow-list pattern.
- **Path-traversal and decompression-bomb protection** on every archive extraction (member-count caps, total-size caps, symlink refusal, resolved-path containment checks).
- **Resource limits** — per-tool timeout, CPU seconds, and memory ceiling (POSIX `rlimit`), with tighter caps automatically applied to anything that actually executes a challenge binary.
- **Competition-mode sandboxing is fail-closed.** Any tool marked `requires_sandbox=True` (dynamic execution, binary-derived transformations) runs inside Docker (`--network none`, capped CPU/memory/pids, no capabilities, read-only-friendly mount) when available. If Docker is *not* available, competition mode returns `BLOCKED_SANDBOX_REQUIRED` — it never silently falls back to running an untrusted binary on the bare host. Development mode allows an explicit, clearly-labeled host fallback for local iteration.
- **Web fetching is origin-locked.** A web challenge authorizes exactly one URL; CYPHER can only ever fetch that origin (scheme + host + port) or same-origin paths derived from it (`/robots.txt`, `/sitemap.xml`), and redirects to a different origin are refused. This holds even if the model is prompt-injected or hallucinates an attacker URL — the loop can only select from pre-registered, operator-authorized targets, so an off-origin string never reaches the fetcher.
- **Prompt-injection defense** — every AI call carries an explicit policy hierarchy (system policy > application policy > tool policy > challenge data) instructing the model that anything from the challenge (description, filenames, tool output, web content) is untrusted data, never an instruction, no matter how it's phrased.
- **Zero auto-submission.** There is no code path anywhere in this repository that submits a flag to an external service. Verified flags are printed for the human to review and submit manually.

---

## Flag verification

A candidate flag becomes `CONFIRMED` only if **all** of the following hold:
1. It matches the configured flag-format pattern (default `NAME{...}`, configurable via `CYPHER_FLAG_REGEX`).
2. It appears **verbatim** in a real tool's stored raw output — never merely asserted by the model in a hypothesis, plan, or interpretation.
3. The evidence it came from meets a minimum relevance threshold.
4. If found via more than one distinct tool, that's recorded as independent corroboration.
5. If it was recovered through a transformation (base64, XOR, etc.), the transformation method is recorded alongside it, so the result is explainable, not just asserted.

This is deliberately conservative because most CTF scoring penalizes wrong submissions more than slow ones. A regression test specifically proves that a model instructed to insist a fake flag is correct — on every single call — never produces a `CONFIRMED` result, because flag extraction is architecturally restricted to real tool stdout/stderr and nothing else.

---

## Artifact-aware recursion

When a tool leaves a new file in the workspace — an archive extractor unpacking a hidden payload, an image tool splitting out a channel — CYPHER notices, hashes it, and (if it's genuinely new content, not a duplicate) turns it into its own investigation target with a fresh hypothesis, up to a bounded depth (4 hops) and artifact count (40). A content-hash cycle guard means a tool that regenerates the same bytes twice is never treated as a new discovery. This is proven end-to-end by a test that chains a real archive extraction into a real base64 decode into a confirmed flag, with the artifact's full provenance (parent tool, evidence ID, depth) intact.

---

## Evidence, state, and resumability

Every challenge gets an isolated workspace (`workspaces/<challenge_id>/`) containing:
- `originals/` — untouched copies of what was submitted
- `extracted/` — anything CYPHER's own intake safely unpacked
- `evidence/` — every tool's raw output, one file per evidence ID, never overwritten
- `state.json` — the full investigation state: hypotheses (with priority, status, and every attempted/successful/failed action), evidence index, discovered artifacts, candidate flags, and the confirmed flag if any

An investigation can be resumed rather than restarted — `state.json` is loaded back in on the next `solve` call against the same workspace.

---

## Configuration

All settings are environment variables (see [`config/settings.py`](src/cypher/config/settings.py)):

| Variable | Default | Purpose |
|---|---|---|
| `CYPHER_OLLAMA_HOST` | `http://localhost:11434` | Ollama server address |
| `CYPHER_OLLAMA_MODEL` | `qwen3:4b` | Model to use |
| `CYPHER_PROVIDER` | `ollama` | `ollama` or `mock` |
| `CYPHER_WORKSPACES` | `./workspaces` | Per-challenge workspace root |
| `CYPHER_MAX_ITERATIONS` | `15` | Default investigation loop budget |
| `CYPHER_FLAG_REGEX` | `[A-Za-z0-9_]{3,20}\{[^{}\s]{1,200}\}` | Configurable flag format |
| `CYPHER_USE_DOCKER` | `0` | `1` to attempt Docker for sandboxed tools |
| `CYPHER_DOCKER_IMAGE` | `cypher-sandbox` | Sandbox image name |
| `CYPHER_SANDBOX_POLICY` | `competition` | `competition` (fail closed) or `development` (explicit host fallback) |

---

## Project layout

```
cypher/
  src/cypher/
    ai/            AIProvider abstraction — ollama.py, mock.py, base.py
    cli/           Command-line entry point
    config/        Environment-driven settings
    core/          Challenge intake, hypotheses, investigation loop, state
    evidence/      Evidence store (raw output + index)
    flags/         Extraction (generous) and verification (conservative)
    tools/         Registry + executor + per-category tool specs
      forensics/ stego/ crypto/ reverse/ audio/ web/ osint/
  tests/           41 tests across security, resilience, and end-to-end scenarios
  sandbox/
    Dockerfile     Sandbox image tool arsenal
  workspaces/       Per-challenge investigation state (git-ignored)
```

---

## Testing

```bash
pytest tests/                # if pytest is available
python tests/_pytest_shim.py # stdlib-only fallback runner (no network required)
```

The suite exercises real behavior, not just imports: a full base64/XOR/nested-archive solve end-to-end, path-traversal and decompression-bomb rejection, competition-mode sandbox blocking (proven against whatever sandboxed tool is actually installed, not hardcoded to one that may be missing), web origin-restriction (including a simulated prompt-injected attacker URL), total-Ollama-outage resilience, and a dedicated regression test proving a persistently fake-flag-asserting model can never produce a false `CONFIRMED`.

---

## Benchmarking

```bash
cypher benchmark                       # bundled synthetic plumbing test — proves the
                                        # core loop still works, NOT a difficulty claim
cypher benchmark --dir ./my-challenges # real challenges, real provider — this number
                                        # is the one that actually means something
```
Each subfolder under `--dir` is one challenge (optionally with a `description.txt`). Tracks solved/status, time, tool calls, and hypothesis count per challenge.

---

## Known limitations

Being direct about what this is *not*, so it isn't discovered the hard way mid-competition:

- **No live-model validation.** Every test in this repo uses a scripted or mock AI provider. Whether your actual local model (`qwen3:4b` or similar) reliably produces usable JSON tool-selections under real conditions is untested — validate this yourself before relying on it.
- **Pwn is static triage plus sandbox-gated stubs**, not automatic exploit generation. Real ROP-chain construction and exploit development are out of scope.
- **OSINT is offline cross-referencing only** — no live public-source search is wired in; "corroboration" means "seen elsewhere in this investigation's own evidence," not "verified against the internet."
- **Web tooling is fetch-only** (headers/body/robots.txt/sitemap) — no authenticated sessions, no JavaScript execution/rendering, no automated form submission.
- **The sandbox image is unverified in this repo's own testi