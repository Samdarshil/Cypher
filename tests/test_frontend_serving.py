"""Tests for the static frontend serving + CORS added to support the
bundled UI. Includes a real (unnormalized) path-traversal attempt sent
via raw http.client, since curl/browsers normalize '../' client-side
before it ever reaches the server -- that normalization must not be
mistaken for the server's own protection.
"""
import http.client
import sys
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.investigation.api import run_server

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


def _start(tmp_path):
    server = run_server(tmp_path / "cases", port=0, static_dir=FRONTEND_DIR)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return server, port


def test_index_html_served_at_root(tmp_path):
    server, port = _start(tmp_path)
    try:
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
        assert "<title>Cypher" in body
    finally:
        server.shutdown()


def test_js_served_with_correct_content_type(tmp_path):
    server, port = _start(tmp_path)
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/app.js")
        assert resp.headers.get("Content-Type") == "application/javascript"
    finally:
        server.shutdown()


def test_cors_headers_present_on_api_response(tmp_path):
    server, port = _start(tmp_path)
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/investigations")
        assert resp.headers.get("Access-Control-Allow-Origin") == "*"
    finally:
        server.shutdown()


def test_head_request_matches_get_headers_without_body(tmp_path):
    server, port = _start(tmp_path)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.request("HEAD", "/app.js")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.getheader("Content-Type") == "application/javascript"
        assert resp.read() == b""
        conn.close()
    finally:
        server.shutdown()


def test_raw_unnormalized_path_traversal_is_blocked(tmp_path):
    """The real test: an actual traversal sequence sent byte-for-byte
    over the wire, bypassing any client-side normalization curl or a
    browser would otherwise apply."""
    server, port = _start(tmp_path)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.putrequest("GET", "/../../../../etc/passwd", skip_host=True)
        conn.putheader("Host", "127.0.0.1")
        conn.endheaders()
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 403
        assert b"forbidden" in body
        conn.close()
    finally:
        server.shutdown()


def test_unknown_path_falls_back_to_index_for_spa_routing(tmp_path):
    server, port = _start(tmp_path)
    try:
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/some/client/side/route").read().decode()
        assert "<title>Cypher" in body  # SPA fallback, not a 404
    finally:
        server.shutdown()
