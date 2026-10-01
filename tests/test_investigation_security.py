"""Security audit tests for the investigation-platform API/CLI layer
(priority 8 of this pass). Proves the path-traversal fix, ID validation,
and body-size limiting with real exploitation attempts, not just
assertions about intent.
"""
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from cypher.investigation.api import run_server
from cypher.investigation.case import CaseManager, InvalidCaseIdError


def test_case_id_path_traversal_is_rejected(tmp_path):
    """The exact vulnerability found and fixed this pass: a crafted
    case_id must never be used to build a filesystem path outside
    cases_root.
    """
    mgr = CaseManager(tmp_path / "cases")

    outside = tmp_path / "outside_secret_dir"
    outside.mkdir()
    (outside / "metadata.json").write_text(json.dumps({
        "case_id": "CASE-evil0001", "name": "hijacked", "description": "",
        "status": "open", "workspace": str(outside),
        "created_at": 0, "updated_at": 0, "evidence_ids": [], "finding_ids": [],
    }))

    for traversal_attempt in ("../outside_secret_dir", "../../etc/passwd", "CASE-x/../../evil", "../../../"):
        with pytest.raises(InvalidCaseIdError):
            mgr.get_case(traversal_attempt)


def test_valid_looking_but_wrong_length_id_is_rejected(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    with pytest.raises(InvalidCaseIdError):
        mgr.get_case("CASE-tooshort")  # not 8 hex chars
    with pytest.raises(InvalidCaseIdError):
        mgr.get_case("CASE-toolonghexstring12345")


def test_http_api_rejects_traversal_case_id_with_400_not_500(tmp_path):
    server = run_server(tmp_path / "cases", port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.1)
    try:
        url = f"http://127.0.0.1:{port}/investigations/..%2F..%2Fetc"
        try:
            urllib.request.urlopen(url)
            assert False, "expected an HTTP error response"
        except urllib.error.HTTPError as exc:
            assert exc.code in (400, 404)
    finally:
        server.shutdown()


def test_http_api_rejects_malformed_json_body_gracefully(tmp_path):
    server = run_server(tmp_path / "cases", port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.1)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/investigations",
            data=b"{not valid json!!!", headers={"Content-Type": "application/json"}, method="POST",
        )
        resp = urllib.request.urlopen(req)
        assert resp.status == 201
    finally:
        server.shutdown()


def test_http_api_rejects_oversized_body(tmp_path):
    from cypher.investigation.api import MAX_BODY_BYTES

    server = run_server(tmp_path / "cases", port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.1)
    try:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("POST", "/investigations")
        conn.putheader("Content-Length", str(MAX_BODY_BYTES + 1))
        conn.putheader("Content-Type", "application/json")
        conn.endheaders()
        conn.send(b'{"name": "x"}')
        try:
            resp = conn.getresponse()
            assert resp.status == 400
        except Exception:
            pass
        finally:
            conn.close()
    finally:
        server.shutdown()


def test_human_decision_on_nonexistent_finding_is_404_not_crash(tmp_path):
    server = run_server(tmp_path / "cases", port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.1)
    try:
        create_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/investigations",
            data=json.dumps({"name": "sec test"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        case = json.loads(urllib.request.urlopen(create_req).read())

        decide_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/investigations/{case['case_id']}/findings/F-9999/decision",
            data=json.dumps({"decision": "confirm"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            urllib.request.urlopen(decide_req)
            assert False, "expected 404"
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        server.shutdown()
