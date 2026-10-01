"""HTTP API (spec §14, completed).

Stdlib-only (http.server) — no new dependency. Real and runnable:
`python -m cypher.investigation.api` starts it on localhost. This is
what a locally-run frontend would talk to (see the frontend contract
doc) — this repo does not ship that frontend yet.

Routes:
  GET  /investigations
  POST /investigations                        {"name", "description"}
  GET  /investigations/{id}
  POST /investigations/{id}/evidence           {"path"} (server-local path)
  POST /investigations/{id}/evidence/upload    multipart form field `file`
  GET  /investigations/{id}/evidence
  POST /investigations/{id}/analysis           {"evidence_id", "tool"}
  GET  /investigations/{id}/analysis           (raw tool results so far)
  GET  /investigations/{id}/observations
  GET  /investigations/{id}/entities
  GET  /investigations/{id}/correlations
  GET  /investigations/{id}/findings
  POST /investigations/{id}/ai-analysis        trigger the AI Analyst
  POST /investigations/{id}/findings/{fid}/decision   {"decision", "note"}
       decision in {"confirm", "reject", "review"}
  GET  /investigations/{id}/timeline
  GET  /investigations/{id}/report             ?format=json|markdown (default json)

Security: non-local binds require CYPHER_ACCESS_TOKEN unless the explicit
CYPHER_PUBLIC_DEMO mode is enabled. Every {id}/{fid} path segment is validated before use (see
case.py's _validate_case_id and this module's _validate_finding_id) --
a prior version of case_id lookup could be made to escape the cases
directory via a crafted ID; that class of bug is fixed at the source
(CaseManager.get_case) and this module never re-derives a path from an
ID itself. JSON bodies are capped at 10 MiB; multipart uploads are separately
bounded by the configured file limit plus 256 KiB of framing.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import ipaddress
import hmac
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cypher.ai.ollama import OllamaProvider
from cypher.investigation.analysis import AnalysisOrchestrator
from cypher.investigation.analyst import AIAnalyst
from cypher.investigation.case import CaseManager, CaseNotFoundError, InvalidCaseIdError
from cypher.investigation.correlation import CorrelationEngine
from cypher.investigation.evidence import EvidenceRegistry
from cypher.investigation.findings import Finding, FindingStore
from cypher.investigation.observation import ObservationStore
from cypher.investigation.report import generate_report, render_markdown
from cypher.investigation.timeline import Timeline
from cypher.tools.registry import build_default_registry

MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_UPLOAD_BYTES = int(os.environ.get("CYPHER_MAX_UPLOAD_BYTES", 20 * 1024 * 1024))
if not 1 <= MAX_UPLOAD_BYTES <= 100 * 1024 * 1024:
    raise RuntimeError("CYPHER_MAX_UPLOAD_BYTES must be between 1 and 104857600 bytes.")
MAX_UPLOAD_REQUEST_BYTES = MAX_UPLOAD_BYTES + 256 * 1024
MAX_UPLOAD_FILENAME_LENGTH = 255
_FINDING_ID_PATTERN = re.compile(r"^F-\d{4}$")


class InvalidFindingIdError(RuntimeError):
    pass


class BodyTooLargeError(RuntimeError):
    pass


class UploadAuthorizationError(RuntimeError):
    pass


def _safe_upload_name(name: str) -> str:
    """Keep a display name while removing client-controlled path components."""
    name = str(name).replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch >= " " and ch not in "\x7f\r\n")
    name = name.strip().strip(".")
    if len(name) > MAX_UPLOAD_FILENAME_LENGTH:
        raise ValueError(f"Filename must be {MAX_UPLOAD_FILENAME_LENGTH} characters or fewer.")
    if not name or name in {".", ".."}:
        raise ValueError("A valid filename is required.")
    return name


def _validate_finding_id(finding_id: str) -> str:
    if not _FINDING_ID_PATTERN.match(finding_id):
        raise InvalidFindingIdError(f"Invalid finding ID: {finding_id!r}")
    return finding_id


def public_demo_enabled() -> bool:
    """Public unauthenticated access is disabled unless explicitly enabled."""
    return os.environ.get("CYPHER_PUBLIC_DEMO", "false").strip().lower() == "true"


class InvestigationAPI:
    """The actual logic, separate from HTTP plumbing so it's directly
    unit-testable without spinning up a server.
    """

    def __init__(self, cases_root: Path, sandbox_policy: str = "competition", ai_provider=None) -> None:
        self.case_manager = CaseManager(cases_root)
        self.registry = build_default_registry()
        self.sandbox_policy = sandbox_policy
        self.ai_provider = ai_provider  # None -> lazily default to Ollama on first AI use
        self._case_parts: dict[str, dict] = {}

    @staticmethod
    def _public_case(case) -> dict:
        data = case.to_dict()
        data.pop("workspace", None)
        return data

    @staticmethod
    def _public_evidence(item) -> dict:
        data = item.to_dict()
        data.pop("stored_path", None)
        return data

    def _parts(self, case_id: str) -> dict:
        if case_id not in self._case_parts:
            case = self.case_manager.get_case(case_id)  # validates + raises CaseNotFoundError
            ev = EvidenceRegistry(case.workspace)
            obs = ObservationStore(case.workspace)
            corr = CorrelationEngine(case.workspace)
            findings = FindingStore(case.workspace)
            timeline = Timeline(case.workspace)
            orchestrator = AnalysisOrchestrator(case.workspace, ev, self.registry, timeline, self.sandbox_policy)
            self._case_parts[case_id] = {
                "case": case, "evidence": ev, "observations": obs, "correlations": corr,
                "findings": findings, "timeline": timeline, "orchestrator": orchestrator,
            }
        return self._case_parts[case_id]

    def list_investigations(self) -> list[dict]:
        return [self._public_case(c) for c in self.case_manager.list_cases()]

    def create_investigation(self, name: str, description: str = "") -> dict:
        case = self.case_manager.create_case(name, description)
        return self._public_case(case)

    def get_investigation(self, case_id: str) -> dict:
        return self._public_case(self.case_manager.get_case(case_id))

    def add_evidence(self, case_id: str, source_path: str) -> dict:
        parts = self._parts(case_id)
        item = parts["evidence"].register_file(Path(source_path))
        parts["timeline"].record(f"Evidence {item.evidence_id} ({item.original_name}) registered", item.evidence_id)
        return self._public_evidence(item)

    def add_uploaded_evidence(self, case_id: str, filename: str, content: bytes) -> dict:
        if len(content) > MAX_UPLOAD_BYTES:
            raise BodyTooLargeError(f"File exceeds the {MAX_UPLOAD_BYTES} byte upload limit.")
        name = _safe_upload_name(filename)
        parts = self._parts(case_id)  # validates the investigation before touching storage
        staging = parts["case"].workspace / "evidence" / ".upload-staging"
        staging.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(dir=staging, prefix="incoming-", delete=False) as fh:
                temp_path = Path(fh.name)
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            item = parts["evidence"].register_file(temp_path, source="browser_upload", original_name=name)
            parts["timeline"].record(f"Evidence {item.evidence_id} ({item.original_name}) uploaded", item.evidence_id)
            return self._public_evidence(item)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def list_evidence(self, case_id: str) -> list[dict]:
        return [self._public_evidence(e) for e in self._parts(case_id)["evidence"].all()]

    def run_analysis(self, case_id: str, evidence_id: str, tool_name: str) -> dict:
        parts = self._parts(case_id)
        result = parts["orchestrator"].analyze(evidence_id, tool_name)
        if result is None:
            parts["timeline"].record(f"Analysis FAILED: {tool_name} on {evidence_id} (validation error)", evidence_id)
            return {"ok": False, "status": "FAILED", "error": "tool validation failed"}

        combined = result.stdout + "\n" + result.stderr
        stored_results = parts["orchestrator"].results.all()
        latest_result_id = stored_results[-1].id if stored_results else None
        observations = parts["observations"].extract_from_result(combined, latest_result_id or "unknown", evidence_id)
        parts["correlations"].rebuild_from_observations(parts["observations"].all())
        if observations:
            parts["timeline"].record(
                f"{len(observations)} observation(s) extracted from {tool_name} on {evidence_id}",
                latest_result_id,
            )
        status = "COMPLETED" if result.exit_code == 0 and not result.timed_out else "FAILED"
        return {
            "ok": result.exit_code == 0, "status": status, "exit_code": result.exit_code,
            "sandbox_mode": result.sandbox_mode, "result_id": latest_result_id,
            "observations_created": [o.to_dict() for o in observations],
        }

    def list_analysis_results(self, case_id: str) -> list[dict]:
        return [r.to_dict() for r in self._parts(case_id)["orchestrator"].results.all()]

    def list_observations(self, case_id: str) -> list[dict]:
        return [o.to_dict() for o in self._parts(case_id)["observations"].all()]

    def list_entities(self, case_id: str) -> list[dict]:
        return [e.to_dict() for e in self._parts(case_id)["correlations"].entities()]

    def list_correlations(self, case_id: str) -> list[dict]:
        return [c.to_dict() for c in self._parts(case_id)["correlations"].correlations()]

    def list_findings(self, case_id: str) -> list[dict]:
        return [f.to_dict() for f in self._parts(case_id)["findings"].all()]

    def run_ai_analysis(self, case_id: str) -> dict:
        parts = self._parts(case_id)
        provider = self.ai_provider or OllamaProvider()
        analyst = AIAnalyst(provider, parts["evidence"], parts["observations"], parts["correlations"], parts["findings"])
        result = analyst.propose_findings()
        parts["timeline"].record(
            f"AI analysis: {len(result.accepted)} finding(s) proposed, {len(result.rejected)} rejected",
        )
        return {
            "accepted": [f.to_dict() for f in result.accepted],
            "rejected": result.rejected,
        }

    def decide_finding(self, case_id: str, finding_id: str, decision: str, note: str | None) -> dict:
        _validate_finding_id(finding_id)
        parts = self._parts(case_id)
        finding: Finding | None = parts["findings"].get(finding_id)
        if finding is None:
            raise KeyError(f"No such finding: {finding_id!r}")

        previous_state = finding.review_state.value
        if decision == "confirm":
            finding.confirm(note)
        elif decision == "reject":
            finding.reject(note)
        elif decision == "review":
            finding.flag_for_review(note)
        else:
            raise ValueError(f"Invalid decision: {decision!r}. Must be confirm/reject/review.")
        parts["findings"].save()
        parts["timeline"].record(
            f"Human decision on {finding_id}: {previous_state} -> {finding.review_state.value}"
            + (f" ({note})" if note else ""),
            finding_id,
        )
        return finding.to_dict()

    def list_timeline(self, case_id: str) -> list[dict]:
        return [e.to_dict() for e in self._parts(case_id)["timeline"].all()]

    def get_report(self, case_id: str) -> dict:
        parts = self._parts(case_id)
        report = generate_report(
            parts["case"], parts["evidence"], parts["observations"],
            parts["correlations"], parts["findings"], parts["timeline"],
        )
        for item in report.get("observed", {}).get("evidence_inventory", []):
            item.pop("stored_path", None)
        report.get("investigation", {}).pop("workspace", None)
        return report


def make_handler(api: InvestigationAPI, static_dir: Path | None = None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _cors_headers(self) -> None:
            # This is a local analyst tool with no auth layer; CORS is
            # opened for localhost dev convenience (the bundled frontend
            # is served from this same process anyway, so same-origin in
            # the normal case -- this only matters if someone points a
            # separately-hosted frontend at this API).
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors_headers()
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_HEAD(self):
            # Same routing as GET, but with the body suppressed -- some
            # tools (curl -I, certain browser prefetch behavior) use HEAD,
            # and it should get the same headers/status as the
            # corresponding GET would, not the framework's generic
            # "unsupported method" response.
            self._suppress_body = True
            try:
                self.do_GET()
            finally:
                self._suppress_body = False

        def _send_json(self, status: int, payload) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self._cors_headers()
            self.end_headers()
            if not getattr(self, "_suppress_body", False):
                self.wfile.write(body)

        def _send_text(self, status: int, text: str, content_type: str = "text/markdown") -> None:
            body = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._cors_headers()
            self.end_headers()
            if not getattr(self, "_suppress_body", False):
                self.wfile.write(body)

        def _read_json_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            if length > MAX_BODY_BYTES:
                raise BodyTooLargeError(f"Request body ({length} bytes) exceeds the {MAX_BODY_BYTES} byte limit.")
            try:
                return json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                return {}

        def _handle_errors(self, fn):
            try:
                fn()
            except CaseNotFoundError as exc:
                self._send_json(404, {"error": str(exc)})
            except BodyTooLargeError as exc:
                self._send_json(413, {"error": str(exc)})
            except (InvalidCaseIdError, InvalidFindingIdError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})
            except KeyError as exc:
                self._send_json(404, {"error": str(exc)})
            except UploadAuthorizationError as exc:
                self._send_json(403, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                self._send_json(500, {"error": "The request could not be completed."})

        def _authorize_upload(self) -> None:
            self._authorize_api()

        def _authorize_api(self) -> None:
            if public_demo_enabled():
                return
            configured = os.environ.get("CYPHER_ACCESS_TOKEN", "")
            peer = self.client_address[0]
            try:
                local = ipaddress.ip_address(peer).is_loopback
            except ValueError:
                local = False
            if local and not configured:
                return
            supplied = self.headers.get("Authorization", "")
            if not configured or not supplied.startswith("Bearer ") or not hmac.compare_digest(supplied[7:], configured):
                raise UploadAuthorizationError("A valid Cypher access token is required.")

        def _read_upload(self) -> tuple[str, bytes]:
            content_type = self.headers.get("Content-Type", "")
            if not content_type.lower().startswith("multipart/form-data;"):
                raise ValueError("Upload must use multipart/form-data.")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ValueError("Invalid Content-Length.") from None
            if length <= 0:
                raise ValueError("No file was provided.")
            if length > MAX_UPLOAD_REQUEST_BYTES:
                raise BodyTooLargeError(f"Upload request exceeds the {MAX_UPLOAD_REQUEST_BYTES} byte limit.")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Upload was interrupted before all bytes arrived.")
            message = BytesParser(policy=policy.default).parsebytes(
                b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + raw
            )
            if not message.is_multipart():
                raise ValueError("Invalid multipart upload.")
            files = []
            for part in message.iter_parts():
                if part.get_param("name", header="content-disposition") != "file":
                    continue
                filename = part.get_filename()
                data = part.get_payload(decode=True) or b""
                if filename is None:
                    raise ValueError("The file part must include a filename.")
                files.append((_safe_upload_name(filename), data))
            if len(files) != 1:
                raise ValueError("Provide exactly one file per upload request.")
            filename, content = files[0]
            if len(content) > MAX_UPLOAD_BYTES:
                raise BodyTooLargeError(f"File exceeds the {MAX_UPLOAD_BYTES} byte upload limit.")
            return filename, content

        def do_GET(self):
            parsed = urlparse(self.path)
            parts = [p for p in parsed.path.split("/") if p]
            query = parse_qs(parsed.query)

            def handle():
                if parts == ["public-config"]:
                    self._send_json(200, {"public_demo": public_demo_enabled()})
                    return
                if parts[:1] == ["investigations"] or parts == ["upload-limits"]:
                    self._authorize_api()
                if parts == ["investigations"]:
                    self._send_json(200, api.list_investigations())
                elif parts == ["upload-limits"]:
                    self._send_json(200, {"max_file_bytes": MAX_UPLOAD_BYTES, "max_files_per_request": 1, "max_filename_length": MAX_UPLOAD_FILENAME_LENGTH})
                elif len(parts) == 2 and parts[0] == "investigations":
                    self._send_json(200, api.get_investigation(parts[1]))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "evidence":
                    self._send_json(200, api.list_evidence(parts[1]))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "analysis":
                    self._send_json(200, api.list_analysis_results(parts[1]))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "observations":
                    self._send_json(200, api.list_observations(parts[1]))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "entities":
                    self._send_json(200, api.list_entities(parts[1]))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "correlations":
                    self._send_json(200, api.list_correlations(parts[1]))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "findings":
                    self._send_json(200, api.list_findings(parts[1]))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "timeline":
                    self._send_json(200, api.list_timeline(parts[1]))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "report":
                    fmt = query.get("format", ["json"])[0]
                    report = api.get_report(parts[1])
                    if fmt == "markdown":
                        self._send_text(200, render_markdown(report))
                    else:
                        self._send_json(200, report)
                elif static_dir is not None and not parts[:1] == ["investigations"]:
                    self._serve_static(parsed.path)
                else:
                    self._send_json(404, {"error": "not found"})

            self._handle_errors(handle)

        def _serve_static(self, url_path: str) -> None:
            # Minimal static file server for the bundled frontend, kept in
            # the same process as the API so `cypher serve` is one command.
            # Path-traversal-safe: resolves the requested path and refuses
            # to serve anything outside static_dir, the same discipline
            # used everywhere else in this codebase for file access.
            rel = url_path.lstrip("/") or "index.html"
            candidate = (static_dir / rel).resolve()
            try:
                candidate.relative_to(static_dir.resolve())
            except ValueError:
                self._send_json(403, {"error": "forbidden"})
                return
            if candidate.is_dir():
                candidate = candidate / "index.html"
            if not candidate.exists():
                # SPA-style fallback: unknown paths serve index.html so
                # client-side routing (if any) can handle them.
                candidate = static_dir / "index.html"
                if not candidate.exists():
                    self._send_json(404, {"error": "not found"})
                    return
            content_types = {
                ".html": "text/html", ".css": "text/css", ".js": "application/javascript",
                ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png",
            }
            ctype = content_types.get(candidate.suffix, "application/octet-stream")
            body = candidate.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self._cors_headers()
            self.end_headers()
            if not getattr(self, "_suppress_body", False):
                self.wfile.write(body)

        def do_POST(self):
            path = urlparse(self.path).path
            parts = [p for p in path.split("/") if p]

            def handle():
                self._authorize_api()
                if len(parts) == 4 and parts[0] == "investigations" and parts[2:] == ["evidence", "upload"]:
                    filename, content = self._read_upload()
                    self._send_json(201, api.add_uploaded_evidence(parts[1], filename, content))
                    return
                if (public_demo_enabled() and len(parts) == 3 and parts[0] == "investigations"
                        and parts[2] == "evidence"):
                    raise UploadAuthorizationError("Server-path evidence ingestion is disabled in public demo mode.")
                body = self._read_json_body()
                if parts == ["investigations"]:
                    self._send_json(201, api.create_investigation(body.get("name", ""), body.get("description", "")))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "evidence":
                    self._send_json(201, api.add_evidence(parts[1], body.get("path", "")))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "analysis":
                    self._send_json(200, api.run_analysis(parts[1], body.get("evidence_id", ""), body.get("tool", "")))
                elif len(parts) == 3 and parts[0] == "investigations" and parts[2] == "ai-analysis":
                    self._send_json(200, api.run_ai_analysis(parts[1]))
                elif (len(parts) == 5 and parts[0] == "investigations" and parts[2] == "findings"
                      and parts[4] == "decision"):
                    self._send_json(200, api.decide_finding(parts[1], parts[3], body.get("decision", ""), body.get("note")))
                else:
                    self._send_json(404, {"error": "not found"})

            self._handle_errors(handle)

    return Handler


def run_server(cases_root: Path, host: str = "127.0.0.1", port: int = 8765, static_dir: Path | None = None) -> ThreadingHTTPServer:
    try:
        externally_reachable = not ipaddress.ip_address(host).is_loopback
    except ValueError:
        externally_reachable = host in {"0.0.0.0", "::"}
    if externally_reachable and not os.environ.get("CYPHER_ACCESS_TOKEN") and not public_demo_enabled():
        raise RuntimeError("Binding Cypher beyond localhost requires CYPHER_ACCESS_TOKEN to be configured.")
    api = InvestigationAPI(cases_root)
    server = ThreadingHTTPServer((host, port), make_handler(api, static_dir))
    return server


_BUNDLED_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "frontend"


if __name__ == "__main__":
    import sys

    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./cases")
    static = _BUNDLED_FRONTEND_DIR if _BUNDLED_FRONTEND_DIR.exists() else None
    srv = run_server(root, static_dir=static)
    print(f"Cypher Investigation API listening on http://127.0.0.1:8765 (cases: {root.resolve()})")
    if static:
        print(f"Frontend served from {static}")
    srv.serve_forever()
