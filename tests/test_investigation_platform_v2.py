"""Tests for §7-14: observations, correlation, AI analyst validation, and
the real (stdlib) HTTP API. The API tests start an actual server on a
real localhost socket and issue real HTTP requests — this proves it
functions, not just that the code parses.
"""
import json
import sys
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.ai.mock import MockProvider
from cypher.investigation.analyst import AIAnalyst
from cypher.investigation.api import run_server
from cypher.investigation.case import CaseManager
from cypher.investigation.correlation import CorrelationEngine
from cypher.investigation.evidence import EvidenceRegistry
from cypher.investigation.findings import FindingStore
from cypher.investigation.observation import ObservationStore, extract_observations_from_text


def test_observation_extraction_is_purely_pattern_based(tmp_path):
    text = "Contact admin@example.com, seen talking to 10.0.0.5 and evil-domain.com over http://evil-domain.com/payload"
    found = extract_observations_from_text(text)
    types = {t for t, _ in found}
    assert "email" in types and "ipv4" in types and "domain" in types and "url" in types
    values = {v for _, v in found}
    assert "admin@example.com" in values
    assert "10.0.0.5" in values


def test_observation_store_persists_and_reloads(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test")
    store = ObservationStore(case.workspace)
    created = store.extract_from_result("connection to 1.2.3.4 observed", "RESULT-1", "EVID-0001")
    assert len(created) == 1
    assert created[0].observation_id == "OBS-0001"

    reloaded = ObservationStore(case.workspace)
    assert len(reloaded.all()) == 1
    assert reloaded.exists_all(["OBS-0001"]) is True
    assert reloaded.exists_all(["OBS-9999"]) is False


def test_correlation_same_value_requires_two_independent_sources(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test")
    store = ObservationStore(case.workspace)
    engine = CorrelationEngine(case.workspace)

    store.extract_from_result("seen: 8.8.8.8", "RESULT-1", "EVID-0001")
    entities, corrs = engine.rebuild_from_observations(store.all())
    assert len(entities) == 1
    assert not any(c.relationship == "same_value" for c in corrs)  # only 1 source so far

    store.extract_from_result("also seen: 8.8.8.8", "RESULT-2", "EVID-0002")
    entities2, corrs2 = engine.rebuild_from_observations(store.all())
    assert any(c.relationship == "same_value" for c in corrs2), (
        "the same IP observed via two distinct tool results must be correlated"
    )


def test_correlation_co_occurring_within_one_result(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test")
    store = ObservationStore(case.workspace)
    engine = CorrelationEngine(case.workspace)

    store.extract_from_result("domain evil.com resolved to 9.9.9.9", "RESULT-1", "EVID-0001")
    _, corrs = engine.rebuild_from_observations(store.all())
    assert any(c.relationship == "co_occurring" for c in corrs)


def test_ai_analyst_rejects_finding_with_fabricated_evidence_id(tmp_path):
    """The core safety requirement of §11: the model referencing an
    EVID/OBS id that doesn't exist must be rejected, not accepted."""
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test")
    ev = EvidenceRegistry(case.workspace)
    obs = ObservationStore(case.workspace)
    corr = CorrelationEngine(case.workspace)
    findings = FindingStore(case.workspace)

    real_file = tmp_path / "real.txt"
    real_file.write_text("some content")
    real_item = ev.register_file(real_file)

    ai = MockProvider()
    ai.queue_response(json.dumps({"findings": [
        {
            "title": "Suspicious activity on nonexistent evidence",
            "severity": "high", "confidence": 0.9,
            "summary": "fabricated", "reasoning": "the model made this up",
            "evidence_refs": ["EVID-9999"],  # does not exist
            "tool_result_refs": [], "observation_refs": [],
        }
    ]}))

    analyst = AIAnalyst(ai, ev, obs, corr, findings)
    result = analyst.propose_findings()

    assert result.accepted == []
    assert len(result.rejected) == 1
    assert "EVID-9999" in result.rejected[0]["reason"]
    assert findings.all() == []


def test_ai_analyst_accepts_finding_with_real_references(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test")
    ev = EvidenceRegistry(case.workspace)
    obs = ObservationStore(case.workspace)
    corr = CorrelationEngine(case.workspace)
    findings = FindingStore(case.workspace)

    real_file = tmp_path / "real.txt"
    real_file.write_text("some content")
    real_item = ev.register_file(real_file)

    ai = MockProvider()
    ai.queue_response(json.dumps({"findings": [
        {
            "title": "File registered for review",
            "severity": "info", "confidence": 0.5,
            "summary": "A file was registered as evidence.",
            "reasoning": f"{real_item.evidence_id} exists in the evidence inventory.",
            "evidence_refs": [real_item.evidence_id],
            "tool_result_refs": [], "observation_refs": [],
        }
    ]}))

    analyst = AIAnalyst(ai, ev, obs, corr, findings)
    result = analyst.propose_findings()

    assert len(result.accepted) == 1
    assert result.accepted[0].review_state.value == "ai_proposed"
    assert findings.all() == result.accepted


def test_ai_analyst_survives_total_ai_outage(tmp_path):
    from cypher.ai.base import AIProvider, AIProviderError

    class AlwaysDown(AIProvider):
        name = "down"
        def generate(self, *a, **k):
            raise AIProviderError("simulated outage")
        def health_check(self):
            return False, "down"

    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test")
    ev = EvidenceRegistry(case.workspace)
    obs = ObservationStore(case.workspace)
    corr = CorrelationEngine(case.workspace)
    findings = FindingStore(case.workspace)

    analyst = AIAnalyst(AlwaysDown(), ev, obs, corr, findings)
    result = analyst.propose_findings()  # must not raise
    assert result.accepted == []
    assert "AI unavailable" in result.rejected[0]["reason"]


def test_real_http_api_end_to_end(tmp_path):
    """Starts an actual server on a real socket and drives the full
    investigation -> evidence -> analysis -> observations flow over real
    HTTP requests."""
    server = run_server(tmp_path / "cases", port=0)  # port=0 -> OS picks a free port
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    base = f"http://127.0.0.1:{actual_port}"

    try:
        # No investigations yet -- must be genuinely empty, not fake data.
        resp = json.loads(urllib.request.urlopen(f"{base}/investigations").read())
        assert resp == []

        create_req = urllib.request.Request(
            f"{base}/investigations", data=json.dumps({"name": "API test case"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        created = json.loads(urllib.request.urlopen(create_req).read())
        case_id = created["case_id"]
        assert created["status"] == "open"

        sample = tmp_path / "sample.txt"
        sample.write_text("evidence containing example.com and 4.3.2.1")

        add_ev_req = urllib.request.Request(
            f"{base}/investigations/{case_id}/evidence",
            data=json.dumps({"path": str(sample)}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        ev_item = json.loads(urllib.request.urlopen(add_ev_req).read())
        assert ev_item["evidence_id"] == "EVID-0001"

        analyze_req = urllib.request.Request(
            f"{base}/investigations/{case_id}/analysis",
            data=json.dumps({"evidence_id": "EVID-0001", "tool": "strings_extract"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        analysis = json.loads(urllib.request.urlopen(analyze_req).read())
        assert analysis["ok"] is True

        observations = json.loads(urllib.request.urlopen(f"{base}/investigations/{case_id}/observations").read())
        obs_values = {o["value"] for o in observations}
        assert "example.com" in obs_values
        assert "4.3.2.1" in obs_values

        timeline = json.loads(urllib.request.urlopen(f"{base}/investigations/{case_id}/timeline").read())
        assert len(timeline) >= 2  # evidence registered + analysis event
    finally:
        server.shutdown()
