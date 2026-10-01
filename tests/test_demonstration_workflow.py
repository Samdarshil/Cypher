"""The complete demonstration workflow (priority 10 of this pass):

    Create Investigation -> Add Evidence -> Run Analysis -> Tool Results
    -> Observations -> Entities -> Correlations -> AI Analysis
    -> Finding Proposal -> Human Decision -> Timeline -> Report

Runs entirely through the public API layer (InvestigationAPI), the same
code path the CLI and HTTP server use — this is not a special-cased
demo, it's the real pipeline. Uses a small benign fixture created
in-test rather than any external download.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.ai.mock import MockProvider
from cypher.investigation.api import InvestigationAPI


def test_complete_demonstration_workflow(tmp_path):
    evidence_dir = tmp_path / "sample_evidence"
    evidence_dir.mkdir()
    sample_log = evidence_dir / "connection_log.txt"
    sample_log.write_text(
        "2024-01-15 08:00:01 connection established to 203.0.113.9\n"
        "2024-01-15 08:00:02 DNS lookup for suspicious-domain.net resolved\n"
        "2024-01-15 08:00:03 outbound request to 203.0.113.9 continued\n"
    )

    api = InvestigationAPI(tmp_path / "cases", sandbox_policy="development")

    case = api.create_investigation("Benign traffic triage demo", "Reproducible test fixture")
    case_id = case["case_id"]
    assert case["status"] == "open"

    ev = api.add_evidence(case_id, str(sample_log))
    assert ev["evidence_id"] == "EVID-0001"
    assert ev["analysis_state"] == "registered"

    analysis_result = api.run_analysis(case_id, "EVID-0001", "strings_extract")
    assert analysis_result["status"] == "COMPLETED"

    results = api.list_analysis_results(case_id)
    assert len(results) == 1
    result_id = results[0]["id"]

    observations = api.list_observations(case_id)
    obs_values = {o["value"] for o in observations}
    assert "203.0.113.9" in obs_values
    assert "suspicious-domain.net" in obs_values

    entities = api.list_entities(case_id)
    assert len(entities) >= 2
    correlations = api.list_correlations(case_id)
    assert any(c["relationship"] == "co_occurring" for c in correlations)

    ip_obs_id = next(o["observation_id"] for o in observations if o["value"] == "203.0.113.9")
    ai = MockProvider()
    ai.queue_response(json.dumps({"findings": [
        {
            "title": "Repeated outbound connection to a single external IP",
            "severity": "low", "confidence": 0.55,
            "summary": "The evidence shows two references to the same external IP address.",
            "reasoning": f"Observation {ip_obs_id} (203.0.113.9) appears twice in {result_id}.",
            "evidence_refs": ["EVID-0001"],
            "tool_result_refs": [result_id],
            "observation_refs": [ip_obs_id],
        }
    ]}))
    api.ai_provider = ai
    ai_result = api.run_ai_analysis(case_id)
    assert len(ai_result["accepted"]) == 1
    assert ai_result["rejected"] == []
    finding_id = ai_result["accepted"][0]["finding_id"]

    findings = api.list_findings(case_id)
    assert findings[0]["review_state"] == "ai_proposed"

    decided = api.decide_finding(case_id, finding_id, "confirm", "Consistent with known outbound proxy IP.")
    assert decided["review_state"] == "human_confirmed"
    assert decided["analyst_note"] == "Consistent with known outbound proxy IP."

    timeline = api.list_timeline(case_id)
    descriptions = [t["description"] for t in timeline]
    assert any("registered" in d for d in descriptions)
    assert any("strings_extract" in d for d in descriptions)
    assert any("AI analysis" in d for d in descriptions)
    assert any("Human decision" in d and "human_confirmed" in d for d in descriptions)

    report = api.get_report(case_id)
    assert len(report["observed"]["evidence_inventory"]) == 1
    assert len(report["observed"]["observations"]) >= 2
    assert report["ai_interpretation"]["proposed_findings"] == []
    assert len(report["human_decisions"]["confirmed_findings"]) == 1
    assert report["human_decisions"]["confirmed_findings"][0]["finding_id"] == finding_id
    assert report["human_decisions"]["rejected_findings"] == []

    from cypher.investigation.report import render_markdown
    md = render_markdown(report)
    assert "Human-Confirmed Findings" in md
    assert "Repeated outbound connection" in md
    assert "NOT confirmed facts" in md
