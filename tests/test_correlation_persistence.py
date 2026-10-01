"""Correlation persistence: the specific bug being fixed. Build ->
persist -> reload in a NEW CorrelationEngine instance (simulating a
process restart) -> rebuild from the same observations -> must NOT
duplicate, and IDs must match exactly across the restart.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.investigation.case import CaseManager
from cypher.investigation.correlation import CorrelationEngine, _deterministic_correlation_id
from cypher.investigation.observation import ObservationStore


def test_correlation_ids_are_deterministic_pure_function():
    id1 = _deterministic_correlation_id("same_value", "ENT-0001")
    id2 = _deterministic_correlation_id("same_value", "ENT-0001")
    assert id1 == id2

    id3 = _deterministic_correlation_id("co_occurring", "ENT-0001", "ENT-0002", "RESULT-1")
    id4 = _deterministic_correlation_id("co_occurring", "ENT-0002", "ENT-0001", "RESULT-1")
    assert id3 == id4, "participant order must not affect the ID"


def test_rebuild_is_idempotent_within_one_process(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test")
    store = ObservationStore(case.workspace)
    engine = CorrelationEngine(case.workspace)

    store.extract_from_result("seen: 8.8.8.8", "RESULT-1", "EVID-0001")
    store.extract_from_result("also seen: 8.8.8.8", "RESULT-2", "EVID-0002")

    _, first_corrs = engine.rebuild_from_observations(store.all())
    same_value = [c for c in first_corrs if c.relationship == "same_value"]
    assert len(same_value) == 1
    first_id = same_value[0].correlation_id

    # Rebuilding again with the SAME observations, same process, must
    # not create a duplicate or a new ID.
    _, second_corrs = engine.rebuild_from_observations(store.all())
    assert second_corrs == []  # nothing NEW was created
    assert len(engine.correlations()) == 1
    assert engine.correlations()[0].correlation_id == first_id


def test_correlation_survives_full_restart_without_duplication(tmp_path):
    """The exact scenario the fix targets: persist, then construct a
    BRAND NEW CorrelationEngine instance (simulating a process restart
    reading from disk), and rebuild from the same observations again.
    """
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test")
    store = ObservationStore(case.workspace)

    store.extract_from_result("domain evil.com resolved to 9.9.9.9", "RESULT-1", "EVID-0001")
    store.extract_from_result("also: evil.com seen again", "RESULT-2", "EVID-0002")

    engine_before_restart = CorrelationEngine(case.workspace)
    entities1, corrs1 = engine_before_restart.rebuild_from_observations(store.all())
    ids_before = {c.correlation_id for c in engine_before_restart.correlations()}
    entity_ids_before = {e.entity_id for e in engine_before_restart.entities()}
    assert len(ids_before) >= 1

    # Simulate restart: a fresh engine instance loading from disk.
    engine_after_restart = CorrelationEngine(case.workspace)
    assert {c.correlation_id for c in engine_after_restart.correlations()} == ids_before
    assert {e.entity_id for e in engine_after_restart.entities()} == entity_ids_before

    # Rebuild again post-restart with the same observations -- must be
    # a no-op (no new correlations, no duplicates, no ID drift).
    new_entities, new_corrs = engine_after_restart.rebuild_from_observations(store.all())
    assert new_entities == []
    assert new_corrs == []
    assert {c.correlation_id for c in engine_after_restart.correlations()} == ids_before
    assert len(engine_after_restart.correlations()) == len(ids_before)  # no duplicates


def test_new_observation_after_restart_adds_without_disturbing_existing(tmp_path):
    mgr = CaseManager(tmp_path / "cases")
    case = mgr.create_case("Test")
    store = ObservationStore(case.workspace)
    store.extract_from_result("seen: 8.8.8.8", "RESULT-1", "EVID-0001")

    engine1 = CorrelationEngine(case.workspace)
    engine1.rebuild_from_observations(store.all())
    ids_before = {c.correlation_id for c in engine1.correlations()}

    # New process, new evidence arrives.
    store2 = ObservationStore(case.workspace)  # reload
    store2.extract_from_result("also seen: 8.8.8.8", "RESULT-2", "EVID-0002")
    engine2 = CorrelationEngine(case.workspace)
    new_entities, new_corrs = engine2.rebuild_from_observations(store2.all())

    assert any(c.relationship == "same_value" for c in new_corrs)
    # Everything from before the restart must still be present untouched.
    ids_after = {c.correlation_id for c in engine2.correlations()}
    assert ids_before.issubset(ids_after)
