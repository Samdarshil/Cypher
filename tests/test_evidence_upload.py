"""HTTP upload contract tests using only the standard library."""
import hashlib
import http.client
import json
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.investigation.api import run_server


def _start(tmp_path):
    server = run_server(tmp_path / "cases", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return server, server.server_address[1]


def _request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    result = response.status, json.loads(response.read() or b"null")
    conn.close()
    return result


def _multipart(filename, content, field="file"):
    boundary = "cypher-test-boundary"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return boundary, body


def _case(port):
    status, case = _request(port, "POST", "/investigations", json.dumps({"name": "Upload test"}), {"Content-Type": "application/json"})
    assert status == 201
    return case["case_id"]


def test_upload_registers_hashed_evidence_and_hides_storage_path(tmp_path):
    server, port = _start(tmp_path)
    try:
        case_id = _case(port)
        content = b"packet evidence\x00\x01"
        boundary, body = _multipart("../capture.pcap", content)
        status, item = _request(port, "POST", f"/investigations/{case_id}/evidence/upload", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        assert status == 201
        assert item["original_name"] == "capture.pcap"
        assert item["size_bytes"] == len(content)
        assert item["sha256"] == hashlib.sha256(content).hexdigest()
        assert item["source"] == "browser_upload"
        assert "stored_path" not in item
        listed_status, listed = _request(port, "GET", f"/investigations/{case_id}/evidence")
        assert listed_status == 200 and listed[0]["evidence_id"] == item["evidence_id"]
        assert "stored_path" not in listed[0]
    finally:
        server.shutdown()


def test_upload_rejects_missing_file_and_bad_investigation(tmp_path):
    server, port = _start(tmp_path)
    try:
        case_id = _case(port)
        boundary, body = _multipart("x.txt", b"x", field="other")
        status, _ = _request(port, "POST", f"/investigations/{case_id}/evidence/upload", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        assert status == 400
        boundary, body = _multipart("x.txt", b"x")
        status, _ = _request(port, "POST", "/investigations/CASE-00000000/evidence/upload", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        assert status == 404
    finally:
        server.shutdown()


def test_upload_limits_are_reported(tmp_path):
    server, port = _start(tmp_path)
    try:
        status, limits = _request(port, "GET", "/upload-limits")
        assert status == 200
        assert limits["max_file_bytes"] > 0
        assert limits["max_files_per_request"] == 1
    finally:
        server.shutdown()


def test_remote_bind_requires_access_token(tmp_path):
    previous = os.environ.pop("CYPHER_ACCESS_TOKEN", None)
    previous_demo = os.environ.pop("CYPHER_PUBLIC_DEMO", None)
    try:
        try:
            run_server(tmp_path / "remote-cases", host="0.0.0.0", port=0)
        except RuntimeError as error:
            assert "CYPHER_ACCESS_TOKEN" in str(error)
        else:
            raise AssertionError("Remote bind should require an access token")
    finally:
        if previous is not None:
            os.environ["CYPHER_ACCESS_TOKEN"] = previous
        if previous_demo is not None:
            os.environ["CYPHER_PUBLIC_DEMO"] = previous_demo


def test_api_routes_require_configured_token(tmp_path):
    previous = os.environ.get("CYPHER_ACCESS_TOKEN")
    previous_demo = os.environ.get("CYPHER_PUBLIC_DEMO")
    os.environ["CYPHER_ACCESS_TOKEN"] = "unit-test-access-token"
    os.environ["CYPHER_PUBLIC_DEMO"] = "false"
    server, port = _start(tmp_path)
    try:
        status, _ = _request(port, "GET", "/investigations")
        assert status == 403
        status, payload = _request(port, "GET", "/investigations", headers={"Authorization": "Bearer unit-test-access-token"})
        assert status == 200 and isinstance(payload, list)
    finally:
        server.shutdown()
        if previous is None:
            os.environ.pop("CYPHER_ACCESS_TOKEN", None)
        else:
            os.environ["CYPHER_ACCESS_TOKEN"] = previous
        if previous_demo is None:
            os.environ.pop("CYPHER_PUBLIC_DEMO", None)
        else:
            os.environ["CYPHER_PUBLIC_DEMO"] = previous_demo


def test_public_demo_allows_tokenless_api_and_upload_but_rejects_server_paths(tmp_path):
    previous_token = os.environ.pop("CYPHER_ACCESS_TOKEN", None)
    previous_demo = os.environ.get("CYPHER_PUBLIC_DEMO")
    os.environ["CYPHER_PUBLIC_DEMO"] = "true"
    server, port = _start(tmp_path)
    try:
        status, config = _request(port, "GET", "/public-config")
        assert status == 200 and config == {"public_demo": True}
        case_id = _case(port)

        local_file = tmp_path / "private-evidence.txt"
        local_file.write_text("must not be registered")
        local_path = str(local_file)
        status, error = _request(port, "POST", f"/investigations/{case_id}/evidence", json.dumps({"path": local_path}), {"Content-Type": "application/json"})
        assert status == 403
        assert local_path not in error["error"]

        boundary, body = _multipart("demo.txt", b"browser upload")
        status, item = _request(port, "POST", f"/investigations/{case_id}/evidence/upload", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        assert status == 201 and item["source"] == "browser_upload"
    finally:
        server.shutdown()
        if previous_token is not None:
            os.environ["CYPHER_ACCESS_TOKEN"] = previous_token
        if previous_demo is None:
            os.environ.pop("CYPHER_PUBLIC_DEMO", None)
        else:
            os.environ["CYPHER_PUBLIC_DEMO"] = previous_demo


def test_public_config_only_exposes_mode_and_public_bind_is_allowed_without_token(tmp_path):
    previous_token = os.environ.pop("CYPHER_ACCESS_TOKEN", None)
    previous_demo = os.environ.get("CYPHER_PUBLIC_DEMO")
    os.environ["CYPHER_PUBLIC_DEMO"] = "true"
    server = run_server(tmp_path / "public-cases", host="0.0.0.0", port=0)
    try:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        status, config = _request(server.server_address[1], "GET", "/public-config")
        assert status == 200 and config == {"public_demo": True}
    finally:
        server.shutdown()
        if previous_token is not None:
            os.environ["CYPHER_ACCESS_TOKEN"] = previous_token
        if previous_demo is None:
            os.environ.pop("CYPHER_PUBLIC_DEMO", None)
        else:
            os.environ["CYPHER_PUBLIC_DEMO"] = previous_demo
