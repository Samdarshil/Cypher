# Cypher

**An AI-assisted cybersecurity investigation platform.** Deterministic security tools + local AI interpretation + evidence-backed findings + a real web UI — with a human analyst always in control of what gets confirmed.

```
cypher serve
```
Then open `http://127.0.0.1:8765` in a browser.

---

## Table of contents

- [What Cypher is](#what-cypher-is)
- [Core principle](#core-principle)
- [Screenshots / what you'll see](#screenshots--what-youll-see)
- [Quickstart](#quickstart)
- [Installation](#installation)
- [The investigation workflow](#the-investigation-workflow)
- [Frontend](#frontend)
- [CLI reference](#cli-reference)
- [HTTP API](#http-api)
- [Architecture](#architecture)
- [AI Analyst and hallucination protection](#ai-analyst-and-hallucination-protection)
- [Correlation engine](#correlation-engine)
- [Security](#security)
- [Reports](#reports)
- [CTF mode (secondary capability)](#ctf-mode-secondary-capability)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)

---

## What Cypher is

Cypher helps a human analyst investigate suspicious digital evidence — a file, a log, a set of artifacts. It runs deterministic security tools (file identification, hashing, string extraction, metadata analysis, and more), extracts indicators automatically, correlates them, and optionally asks a local AI model to interpret what's been found. The AI can *propose* a finding; only a human can *confirm* one.

Cypher's earlier phase was a CTF-solving CLI. That subsystem still exists (`cypher solve <challenge>`) and still works, but the investigation platform described here is now the primary product.

## Core principle

**Evidence beats model confidence.** A `Finding` object cannot exist without a real reference to evidence or a tool result — the code enforces this structurally (`FindingStore.create()` raises `InsufficientEvidenceError` if you try to construct one with none), not just by convention. Every AI-proposed finding is independently checked: if the model cites an evidence ID that doesn't actually exist, the whole finding is rejected before it's ever stored. Findings stay labeled `ai_proposed` until a human explicitly confirms, rejects, or flags them — nothing automates that transition.

Every report and every screen in the UI keeps three things visibly separate: **what was observed** (deterministic, true regardless of AI), **what the AI interpreted** (a hypothesis, not a fact), and **what a human decided**.

## Screenshots / what you'll see

No screenshots are included in this repo — I want to be precise about what's actually been verified: the UI's data layer has been tested end-to-end against a real running backend (see [Testing](#testing)), but I have not personally clicked through it in a browser, since I built this without one available to me. The code is careful, state-driven, and has real empty/loading/error states throughout — but "verified to render correctly" and "verified to behave correctly" are two different claims, and I'm only making the second one with full confidence. Run `cypher serve` and judge the first yourself; if something looks off, it's a real bug to report, not a hedge.

## Quickstart

```bash
pip install -e .
cypher serve
# open http://127.0.0.1:8765
```

That's it — one command runs the API and the bundled web UI together. No investigations exist until you create one; the dashboard will say exactly that.

## Installation

- Python 3.10+
- [Ollama](https://ollama.com), for the AI Analyst (optional — deterministic analysis and the whole UI work without it; only the "Run AI Analysis" button needs it)
- Docker, for tools flagged `requires_sandbox` (optional in development mode; in competition/production mode a sandbox-required tool with no Docker available fails closed rather than running unsandboxed)

```bash
git clone <this-repo> && cd cypher
pip install -e .
ollama pull qwen3:4b     # optional; swap models via CYPHER_OLLAMA_MODEL
cypher doctor            # environment readiness report
cypher serve
```

## The investigation workflow

```
Create Investigation
        ↓
Add Evidence        (hashed, MIME-typed, safely copied into an isolated case workspace)
        ↓
Run Analysis        (deterministic tools — reused, sandboxed, timeout-limited)
        ↓
Tool Results        (raw output preserved, always)
        ↓
Observations        (deterministic pattern extraction: emails, IPs, domains, hashes)
        ↓
Entities + Correlations   (same-value and co-occurrence, both evidence-traceable)
        ↓
AI Analyst          (interprets the above, proposes findings — never invents evidence)
        ↓
Human Decision       (confirm / reject / flag for review — explicit, persisted)
        ↓
Timeline + Report    (three-way separation: observed / AI / human)
```

This works **with zero AI involvement** — deterministic analysis, evidence, observations, correlations, and reports all function if Ollama is offline. AI adds interpretation on top; it's never a dependency for the core workflow.

## Frontend

A real, working, no-build-step web UI ships in `frontend/` — vanilla JavaScript (ES modules), no framework, no bundler, no `npm install` required. Dark professional aesthetic: sidebar navigation, a dashboard, per-investigation tabs (Overview, Evidence, Analysis, Observations, Correlations, Findings, AI Analyst, Timeline, Report), a command palette (`Ctrl/Cmd+K`), toasts, and modals — every screen driven entirely by real API responses, with no hardcoded data anywhere. Empty investigations genuinely say "No investigations yet"; a case with no evidence says "Add evidence to begin analysis"; nothing is faked.

`cypher serve` runs the API and serves this frontend from the same process. The Evidence Explorer supports file selection, drag-and-drop, per-file progress, and server-side SHA-256 registration. Open `http://127.0.0.1:8765` for local use. The API refuses a non-local bind without `CYPHER_ACCESS_TOKEN`; durable hosted evidence also requires a persistent disk. See [deployment and evidence storage](docs/deployment.md) before exposing the service.

**How this was actually verified**, precisely: `scripts/verify_frontend_api.mjs` imports the real `frontend/api.js` module into Node and drives it — with Node's native `fetch` — against a real, running instance of the Python backend, asserting on real responses (investigation creation, evidence registration, tool execution, observation extraction, correlation, report generation, and both the 404 and 400 error paths). This proves the frontend's entire data layer genuinely works against the real API. What it does *not* prove is anything about rendering, layout, or click-through interaction, since that needs an actual browser, which wasn't available while building this. Both JS files also pass `node --check` (syntax validation).

## CLI reference

| Command | Purpose |
|---|---|
| `cypher serve` | Start the HTTP API + web UI (one command) |
| `cypher investigation create/list/show` | Case management |
| `cypher evidence add/list` | Register and list evidence |
| `cypher analysis run/status` | Run a deterministic tool; list results so far |
| `cypher observations list` | Extracted indicators |
| `cypher correlations list` | Deterministic same-value / co-occurrence relationships |
| `cypher findings list` / `cypher finding show/decide` | Findings and human review |
| `cypher ai-analysis` | Trigger the AI Analyst |
| `cypher timeline` | Chronological event log |
| `cypher report --format json\|markdown` | Full investigation report |
| `cypher solve / inspect / doctor / benchmark` | CTF mode (unchanged, see below) |

All investigation commands accept `--cases-dir` (default `./cases`).

## HTTP API

Full contract — every endpoint, object shape, ID format, state enum, and error response — is documented in [`docs/frontend-contract.md`](docs/frontend-contract.md). Stdlib-only (`http.server`), CORS-enabled, no framework dependency. There is no push mechanism (no WebSocket/SSE); the frontend polls after actions that change state.

## Architecture

```
investigation/
  case.py         Investigation/Case model + CaseManager (ID-validated, path-traversal-proof)
  evidence.py      Evidence registration, hashing, EVID- identifiers
  observation.py   Deterministic pattern extraction from tool output
  correlation.py   Entity + Correlation engine (deterministic IDs, not a graph DB)
  findings.py      Structured Finding model (cannot exist without evidence refs)
  analyst.py       AI Analyst — structured output, hallucination rejection
  analysis.py      Orchestrates evidence -> tool -> result -> timeline
  timeline.py      Chronological event log
  report.py        Deterministic report generator (three-way section separation)
  api.py           Stdlib HTTP API + static frontend serving

frontend/          Vanilla JS web UI, no build step
tools/             Reused as-is from the CTF-era build: registry, sandboxed
                   executor, and specialist tool sets
ai/                Reused as-is: AIProvider abstraction, OllamaProvider, MockProvider
```

Nothing in `tools/` or `ai/` was rewritten for the investigation-platform pivot — they were already correct and reused directly.

## AI Analyst and hallucination protection

The AI Analyst is shown real structured context (evidence inventory, observations, correlations) and asked for JSON-formatted findings. Before any proposal becomes a `Finding`:
- Every `evidence_refs`/`observation_refs` ID is checked against what **actually exists** in that case. A fabricated ID gets the whole finding rejected, with the reason recorded.
- Malformed JSON, an invalid severity, or a non-numeric confidence causes that one proposal to be skipped — never a crash, never the rest of the batch.
- A total AI outage (Ollama down, model missing, timeout) returns zero accepted findings with a logged reason — the rest of the investigation, including the UI, remains fully usable.

## Correlation engine

Two deterministic rules, not a graph database:
- **same_value** — the same entity (type+value) observed via more than one independent tool result.
- **co_occurring** — two different entities appearing in the same tool result.

Correlation IDs are deterministic (a hash of the rule + participant identities), not sequential — rebuilding from the same observations after a full process restart produces the exact same IDs, never duplicates. Proven with a test that discards the in-memory engine and reconstructs it from disk mid-test.

## Security

- Every `case_id`/`finding_id` used anywhere is validated against a strict format (`CASE-{8 hex}`, `F-{4 digits}`) before being used to construct a filesystem path or perform a lookup. A crafted `case_id` like `../../etc` is rejected outright — found and fixed during an audit pass, with a regression test that demonstrates the actual exploit shape.
- The bundled frontend's static-file server is separately path-traversal-tested with a raw, unnormalized traversal sequence sent via `http.client` (bypassing the client-side normalization curl/browsers apply, which would otherwise mask the check).
- Request bodies are capped at 10MB to prevent a trivial memory-exhaustion DoS.
- All tool execution goes through the same sandboxed, timeout-limited, argv-safe executor as the CTF subsystem — unchanged, not weakened.
- CORS is open (`*`) for local development convenience; there is no auth layer. **Do not expose `cypher serve` beyond localhost/a trusted network without adding one.**
- The evidence-add endpoint takes a server-local filesystem path — this is a local analyst tool, not a public upload service.

## Reports

`cypher report <id> --format markdown|json`, or the Report tab in the UI (with a one-click Markdown download). Every report structurally separates OBSERVED / AI INTERPRETATION / HUMAN DECISIONS as distinct sections. The report generator is fully deterministic — it never calls an AI provider and never invents a recommendation beyond a small, evidence-conditioned set.

## CTF mode (secondary capability)

The original CTF-solving subsystem (`cypher solve/inspect/doctor/benchmark`) is unchanged and fully functional — investigation loop, hypothesis lifecycle, tool arsenal, and flag verification, all preserved as a secondary capability.

## Testing

```bash
python tests/_pytest_shim.py                          # Python suite, stdlib-only, no network required
node scripts/verify_frontend_api.mjs <backend_url>     # frontend data-layer vs. a REAL running backend
```

**86 Python tests**, including upload validation, access-token enforcement, a real HTTP server driven with real requests, path-traversal protections, correlation persistence, AI resilience, and end-to-end investigation workflows. Some tool-backed tests need optional system utilities such as Docker, ImageMagick, `file`, and `grep`; see the actual test result for environment-specific failures.

**16 frontend integration checks** (`scripts/verify_frontend_api.mjs`), run against a live backend instance, covering the full CRUD/analysis/report lifecycle plus both the 404 and 400 error paths.

## Project layout

```
cypher/
  src/cypher/
    investigation/   The platform: case, evidence, observation, correlation,
                      findings, analyst, analysis, timeline, report, api
    tools/            Reused: registry, sandboxed executor, specialist tools
    ai/                Reused: AIProvider, OllamaProvider, MockProvider
    core/, flags/      CTF-mode subsystem (unchanged)
    cli/               main.py (CTF commands) + investigation_commands.py
  frontend/            Web UI: index.html, styles.css, app.js, api.js
  scripts/
    verify_frontend_api.mjs   Node-based frontend-vs-real-backend integration check
  tests/               81 tests
  docs/
    frontend-contract.md      Exact API contract
  sandbox/
    Dockerfile         Tool arsenal for sandboxed execution
```

## Known limitations

Being direct:
- **No real-browser click-through verification.** The frontend's logic is written carefully, syntax-validated, and its entire data layer is proven against a real backend via Node — but I have not personally opened it in a browser and interacted with it, since none was available while building this. If you find a rendering or interaction bug, it's real — please report it.
- **No live-model validation of the AI Analyst.** All tests use scripted/mock providers; real Ollama JSON-reliability for this specific prompt shape is untested.
- **No auth layer** on the HTTP API — local-trust-only by design, today.
- **No investigation status transition endpoint** — `open → analyzing → review → closed` states exist but nothing currently moves a case between them (the UI shows whatever status a case has; there's no "close investigation" button yet).
- **No pagination** on any list endpoint.
- **Correlation rules are intentionally minimal** (2 rules) — real analyst workflows will likely want more (e.g. temporal proximity, process-lineage).

## Roadmap

Real-browser QA pass (the highest-value remaining item, now that the frontend exists to test), investigation status transitions, an auth layer if this ever needs to run beyond localhost, additional correlation rules, live-model validation of the AI Analyst against a real Ollama instance, and pagination if/when case sizes warrant it.
