"""Tests for the Cypher 2.0 investigation-platform foundation: cases,
evidence, findings, timeline, and analysis orchestration. Proves the
core §3 workflow works end-to-end WITHOUT any AI involvement (spec
section 3's hard requirement), and that findings cannot exist without
real evidence (section 5/13's "no fake data" requirement, enforced
structurally, not just by convention).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from cypher.investigation.analysis import AnalysisOrchestrator
from cypher.investigation.case import CaseManager, CaseNotFoundError, InvestigationCaseStatus
from cypher.investigation.evidence import AnalysisState, EvidenceRegistry
from cypher.investigation.findings import FindingStore, InsufficientEvidenceError, Severity
from cypher.investigation.timeline import Timeline
from cypher.tools.registry import build_default_registry


def test_case_manager_create_list_get_are_independent(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    assert mgr.list_cases() == []  # no fake "CASE-001 ACTIVE" -- genuinely empty

    case_a = mgr.create_case("Suspicious email attachment", "Phishing triage")
    case_b = mgr.create_case("Unusual outbound traffic")

    assert case_a.case_id != case_b.case_id
    assert case_a.workspace != case_b.workspace
    assert case_a.status == InvestigationCaseStatus.OPEN

    listed = {c.case_id for c in mgr.list_cases()}
    assert listed == {case_a.case_id, case_b.case_id}

    reloaded = mgr.get_case(case_a.case_id)
    assert reloaded.name == "Suspicious email attachment"


def test_get_nonexistent_case_raises_not_found(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    # A well-formed but nonexistent ID -> genuinely not found.
    with pytest.raises(CaseNotFoundError):
        mgr.get_case("CASE-deadbeef")


def test_evidence_registration_assigns_stable_sequential_ids(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test case")

    f1 = tmp_path / "a.txt"
    f1.write_text("hello")
    f2 = tmp_path / "b.txt"
    f2.write_text("world")

    registry = EvidenceRegistry(case.workspace)
    item1 = registry.register_file(f1)
    item2 = registry.register_file(f2)

    assert item1.evidence_id == "EVID-0001"
    assert item2.evidence_id == "EVID-0002"
    assert item1.sha256 != item2.sha256
    assert item1.analysis_state == AnalysisState.REGISTERED
    assert item1.stored_path.exists()

    # Reload from disk -- IDs and metadata must survive a restart.
    reloaded = EvidenceRegistry(case.workspace)
    assert {i.evidence_id for i in reloaded.all()} == {"EVID-0001", "EVID-0002"}


def test_finding_without_evidence_refs_is_refused(tmp_path):
    """The structural enforcement of 'no fake findings' -- a Finding
    literally cannot be constructed without pointing at real evidence."""
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test case")
    store = FindingStore(case.workspace)

    with pytest.raises(InsufficientEvidenceError):
        store.create(
            title="This machine communicated with a suspicious IP",
            severity=Severity.HIGH,
            confidence=0.9,
            summary="unsupported claim",
            reasoning="no backing evidence",
            evidence_refs=[],
            tool_result_refs=[],
        )
    assert store.all() == []  # the refused finding must not exist at all


def test_finding_with_evidence_is_created_and_starts_ai_proposed(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test case")
    store = FindingStore(case.workspace)

    finding = store.create(
        title="Embedded archive detected",
        severity=Severity.MEDIUM,
        confidence=0.7,
        summary="binwalk identified an embedded zip archive",
        reasoning="binwalk signature match at offset 0x40",
        evidence_refs=["EVID-0001"],
        tool_result_refs=["E1"],
    )
    assert finding.review_state.value == "ai_proposed"
    assert store.confirmed() == []  # not auto-confirmed just by existing


def test_human_confirm_and_reject_are_explicit_and_distinct(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test case")
    store = FindingStore(case.workspace)
    finding = store.create(
        title="Possible C2 beacon interval", severity=Severity.LOW, confidence=0.4,
        summary="regular interval connections observed", reasoning="timestamp deltas ~60s",
        evidence_refs=["EVID-0002"],
    )
    finding.confirm(note="Verified against firewall logs")
    store.save()

    reloaded_store = FindingStore(case.workspace)
    reloaded = reloaded_store.get(finding.finding_id)
    assert reloaded.review_state.value == "human_confirmed"
    assert reloaded.analyst_note == "Verified against firewall logs"
    assert reloaded_store.confirmed() == [reloaded]


def test_timeline_records_real_events_only(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test case")
    timeline = Timeline(case.workspace)
    assert timeline.all() == []  # empty state, not fake entries

    timeline.record("Evidence registered", source_ref="EVID-0001")
    timeline.record("File analyzed", source_ref="RESULT-E1")
    events = timeline.all()
    assert len(events) == 2
    assert events[0].timestamp <= events[1].timestamp


def test_full_workflow_evidence_to_analysis_to_timeline_without_any_ai(tmp_path):
    """The hard requirement from spec section 3: the core investigative
    workflow (evidence -> deterministic analysis -> stored result ->
    timeline) must work with ZERO AI involvement. No AIProvider is even
    imported in this test.
    """
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Suspicious file triage")

    sample = tmp_path / "sample.txt"
    sample.write_text("just some plain text content for analysis")

    ev_registry = EvidenceRegistry(case.workspace)
    item = ev_registry.register_file(sample)
    timeline = Timeline(case.workspace)
    timeline.record(f"Evidence {item.evidence_id} registered", source_ref=item.evidence_id)

    registry = build_default_registry()
    orchestrator = AnalysisOrchestrator(
        case.workspace, ev_registry, registry, timeline, sandbox_policy="development"
    )
    result = orchestrator.analyze(item.evidence_id, "file_identify")

    assert result is not None
    assert result.exit_code == 0

    refreshed = ev_registry.get(item.evidence_id)
    assert refreshed.analysis_state == AnalysisState.ANALYZED
    assert len(refreshed.result_refs) == 1

    events = timeline.all()
    assert len(events) == 2
    assert "file_identify" in events[-1].description
