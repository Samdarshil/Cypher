# Frontend contract

This document is the exact contract a future frontend consumes. No
frontend ships with this repository yet — see the README's "Frontend
status" section for why. This doc exists so building one never requires
reverse-engineering the backend.

## Starting the backend

```bash
cypher serve                          # http://127.0.0.1:8765, ./cases
cypher serve --host 0.0.0.0 --port 9000 --cases-dir /path/to/cases
```

It's a plain stdlib `http.server` process. No auth layer exists — this
is a local analyst tool, not a multi-tenant service. Do not expose it
beyond localhost/a trusted network without adding one.

## IDs

| Prefix | Format | Example | Notes |
|---|---|---|---|
| Investigation | `CASE-{8 hex chars}` | `CASE-d9ba1146` | Rejected with 400 if malformed — never used to build a path unless it passes this exact format check |
| Evidence | `EVID-{4 digits}` | `EVID-0001` | Sequential per case |
| Analysis result | `E{n}` | `E1` | Sequential per case; this is the raw-tool-output store shared with the CTF-era `EvidenceStore` |
| Observation | `OBS-{4 digits}` | `OBS-0001` | Sequential per case |
| Entity | `ENT-{4 digits}` | `ENT-0001` | Sequential per case; stable across restarts (same type+value -> same ID) |
| Correlation | `CORR-{12 hex chars}` | `CORR-f98fb3b48701` | **Deterministic**, not sequential — a hash of (relationship, participant IDs). Same correlation always gets the same ID, even across a full process restart. |
| Finding | `F-{4 digits}` | `F-0001` | Sequential per case |
| Timeline event | `T-{4 digits}` | `T-0001` | Sequential per case |

## Investigation states

`open` → `analyzing` → `review` → `closed` (enum: `InvestigationCaseStatus`). Nothing currently transitions a case automatically between these — no endpoint updates status today; only creation and read are wired up.

## Analysis states (per evidence item)

`registered` → `analyzing` → `analyzed` | `error` (enum: `AnalysisState`). Maps conceptually to NOT_STARTED / RUNNING / COMPLETED / FAILED.

## Finding review states

`ai_proposed` → `human_confirmed` | `human_rejected` | `needs_review` (enum: `ReviewState`). **Only a human decision transitions out of `ai_proposed`** — nothing in the codebase does this automatically. A `Finding` cannot even be constructed without at least one real `evidence_refs` or `tool_result_refs` entry — `FindingStore.create()` raises `InsufficientEvidenceError` otherwise.

## Endpoints

All bodies/responses are JSON except `GET .../report?format=markdown`, which returns `text/markdown`.

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/investigations` | — | `[InvestigationCase, ...]` (empty array if none — never fake data) |
| POST | `/investigations` | `{"name", "description"?}` | `InvestigationCase`, 201 |
| GET | `/investigations/{id}` | — | `InvestigationCase` |
| POST | `/investigations/{id}/evidence` | `{"path"}` (server-local filesystem path) | `EvidenceItem`, 201 |
| GET | `/investigations/{id}/evidence` | — | `[EvidenceItem, ...]` |
| POST | `/investigations/{id}/analysis` | `{"evidence_id", "tool"}` | `{"ok", "status", "exit_code", "sandbox_mode", "result_id", "observations_created": [Observation, ...]}` |
| GET | `/investigations/{id}/analysis` | — | `[{"id", "source_tool", "input_ref", "summary", ...}, ...]` (raw tool results) |
| GET | `/investigations/{id}/observations` | — | `[Observation, ...]` |
| GET | `/investigations/{id}/entities` | — | `[Entity, ...]` |
| GET | `/investigations/{id}/correlations` | — | `[Correlation, ...]` |
| GET | `/investigations/{id}/findings` | — | `[Finding, ...]` |
| POST | `/investigations/{id}/ai-analysis` | — | `{"accepted": [Finding, ...], "rejected": [{"reason", "raw"}, ...]}` |
| POST | `/investigations/{id}/findings/{fid}/decision` | `{"decision": "confirm"\|"reject"\|"review", "note"?}` | `Finding` (updated) |
| GET | `/investigations/{id}/timeline` | — | `[TimelineEvent, ...]` |
| GET | `/investigations/{id}/report` | — (query `?format=json\|markdown`, default json) | full report object, or Markdown text |

## Object shapes

**InvestigationCase**: `case_id, name, description, status, workspace, created_at, updated_at, evidence_ids, finding_ids`

**EvidenceItem**: `evidence_id, original_name, stored_path, size_bytes, sha256, mime_type, source, ingested_at, analysis_state, result_refs`

**Observation**: `observation_id, type, value, source_result_id, evidence_id`. `type` is one of: `email, url, domain, ipv4, sha256, md5_or_sha1`.

**Entity**: `entity_id, entity_type, value, observation_ids`

**Correlation**: `correlation_id, relationship, entity_ids, observation_ids, reasoning`. `relationship` is `same_value` or `co_occurring`. `reasoning` is a plain-English, deterministically-generated explanation — safe to render directly.

**Finding**: `finding_id, title, severity, confidence, summary, reasoning, evidence_refs, tool_result_refs, review_state, analyst_note, created_at, updated_at`. `severity` is one of `info|low|medium|high|critical`. `confidence` is a float 0–1, the AI's self-reported number — not a system-verified probability.

**TimelineEvent**: `event_id, timestamp, description, source_ref`. `source_ref` is nullable.

**Report** (`GET .../report`): top-level keys `investigation`, `observed` (evidence_inventory/observations/entities/correlations/timeline), `ai_interpretation` (proposed_findings/needs_review_findings), `human_decisions` (confirmed_findings/rejected_findings), `recommended_next_steps`. **A frontend must render these three sections visually distinctly** — this structural separation exists specifically so AI output can never be displayed as if it were a confirmed fact.

## Error responses

All errors are `{"error": "<message>"}`.

| Status | Meaning |
|---|---|
| 400 | Malformed ID (case_id must match `CASE-{8 hex}`, finding_id `F-{4 digits}`), invalid `decision` value, oversized request body (>10MB) |
| 404 | Investigation/finding not found |
| 500 | Unexpected server error (message is the exception string, no stack trace) |

A malformed JSON request body does **not** error — it's treated as an empty object `{}`, so missing-required-field validation (e.g. empty `name`) applies instead. Decide in the frontend whether to pre-validate before sending.

## Activity / "live" updates

**There is no push mechanism (no WebSocket, no SSE) implemented.** A frontend must poll the relevant `GET` endpoints (e.g. `/timeline`, `/findings`) after triggering a `POST` action. The "Live Analysis Activity" experience described in the product spec is achievable this way (poll every N seconds while an operation is in flight) but nothing in this backend currently pushes state — polling is a frontend implementation detail, not a backend feature.

## What's deliberately NOT here yet

- No investigation status transition endpoint (`open → analyzing → review → closed` is defined but nothing calls it)
- No auth/session layer
- No pagination on any list endpoint (fine at analyst-local scale, would need addressing before any multi-user or large-case use)
