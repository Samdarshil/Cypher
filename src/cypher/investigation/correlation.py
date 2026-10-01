"""Entity + Correlation engine (spec §8).

Deliberately NOT a graph database — a simple persistent model that can
later power a graph visualization.

Correlation IDs are DETERMINISTIC: derived from a stable hash of
(relationship, sorted participant identities), never from an
incrementing counter. This is the fix for the earlier limitation where
an in-memory-only dedup set meant a restart could recreate the same
logical correlation under a new ID. Because the ID itself encodes
"what this correlation IS", checking "does this correlation already
exist" is just a dict lookup on the persisted store — no separate
cache, no process-memory state required for correctness. Rebuilding
from the same observations is therefore naturally idempotent: same
inputs -> same ID -> same dict slot, not a duplicate.

Entity IDs remain sequential (ENT-0001, ...) since they're already
stable across restarts via `_entity_by_key` (a (type, value) -> id
map that's rebuilt from persisted entities on load) — that part had no
bug, so it's unchanged.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from cypher.investigation.observation import Observation


@dataclass
class Entity:
    entity_id: str            # "ENT-0001"
    entity_type: str          # normalized from Observation.type
    value: str
    observation_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"entity_id": self.entity_id, "entity_type": self.entity_type,
                 "value": self.value, "observation_ids": self.observation_ids}

    @classmethod
    def from_dict(cls, d: dict) -> "Entity":
        return cls(**d)


@dataclass
class Correlation:
    correlation_id: str       # "CORR-<12 hex chars>" -- deterministic, see module docstring
    relationship: str         # "same_value" | "co_occurring"
    entity_ids: list[str]
    observation_ids: list[str]
    reasoning: str

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id, "relationship": self.relationship,
            "entity_ids": self.entity_ids, "observation_ids": self.observation_ids,
            "reasoning": self.reasoning,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Correlation":
        return cls(**d)


def _deterministic_correlation_id(relationship: str, *identity_parts: str) -> str:
    """Stable across processes and restarts: same rule + same
    participants -> same ID, always. sorted() on the parts the caller
    passes in makes participant order irrelevant (A,B correlates the
    same as B,A).
    """
    canonical = relationship + "|" + "|".join(sorted(identity_parts))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"CORR-{digest}"


class CorrelationEngine:
    def __init__(self, case_workspace: Path) -> None:
        self.case_workspace = Path(case_workspace)
        self.dir = self.case_workspace / "correlations"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._entities: dict[str, Entity] = {}
        self._entity_by_key: dict[tuple[str, str], str] = {}  # (type, value) -> entity_id
        self._correlations: dict[str, Correlation] = {}
        self._entity_counter = itertools.count(1)
        self._load()

    def rebuild_from_observations(self, observations: list[Observation]) -> tuple[list[Entity], list[Correlation]]:
        """Deterministic, idempotent: re-derive entities and correlations
        from the full observation set. Safe to call repeatedly as new
        evidence/observations arrive, and safe across a full process
        restart (reload from disk, call again with the same
        observations) — neither path produces duplicates, because
        correlation identity IS the dedup key, not a side cache.
        """
        new_entities: list[Entity] = []
        for obs in observations:
            key = (obs.type, obs.value)
            if key not in self._entity_by_key:
                eid = f"ENT-{next(self._entity_counter):04d}"
                entity = Entity(entity_id=eid, entity_type=obs.type, value=obs.value)
                self._entities[eid] = entity
                self._entity_by_key[key] = eid
                new_entities.append(entity)
            entity = self._entities[self._entity_by_key[key]]
            if obs.observation_id not in entity.observation_ids:
                entity.observation_ids.append(obs.observation_id)

        new_correlations: list[Correlation] = []
        obs_by_id = {o.observation_id: o for o in observations}

        # Rule 1: SAME_VALUE -- entity seen via >1 distinct source result.
        for entity in self._entities.values():
            source_results = {obs_by_id[oid].source_result_id for oid in entity.observation_ids if oid in obs_by_id}
            if len(source_results) > 1:
                cid = _deterministic_correlation_id("same_value", entity.entity_id)
                if cid not in self._correlations:
                    corr = Correlation(
                        correlation_id=cid, relationship="same_value",
                        entity_ids=[entity.entity_id], observation_ids=sorted(entity.observation_ids),
                        reasoning=(
                            f"{entity.entity_type} '{entity.value}' was independently observed via "
                            f"{len(source_results)} separate tool results: {', '.join(sorted(source_results))}."
                        ),
                    )
                    self._correlations[cid] = corr
                    new_correlations.append(corr)

        # Rule 2: CO_OCCURRING -- two different entities in the same result.
        entities_by_result: dict[str, set[str]] = defaultdict(set)
        for entity in self._entities.values():
            for oid in entity.observation_ids:
                obs = obs_by_id.get(oid)
                if obs:
                    entities_by_result[obs.source_result_id].add(entity.entity_id)
        for result_id, entity_ids in entities_by_result.items():
            ids_sorted = sorted(entity_ids)
            for i in range(len(ids_sorted)):
                for j in range(i + 1, len(ids_sorted)):
                    e1, e2 = self._entities[ids_sorted[i]], self._entities[ids_sorted[j]]
                    cid = _deterministic_correlation_id("co_occurring", e1.entity_id, e2.entity_id, result_id)
                    if cid in self._correlations:
                        continue
                    corr = Correlation(
                        correlation_id=cid, relationship="co_occurring",
                        entity_ids=sorted([e1.entity_id, e2.entity_id]),
                        observation_ids=sorted(
                            oid for oid in (e1.observation_ids + e2.observation_ids)
                            if obs_by_id.get(oid) and obs_by_id[oid].source_result_id == result_id
                        ),
                        reasoning=(
                            f"{e1.entity_type} '{e1.value}' and {e2.entity_type} '{e2.value}' both "
                            f"appeared in the same tool result ({result_id})."
                        ),
                    )
                    self._correlations[cid] = corr
                    new_correlations.append(corr)

        if new_entities or new_correlations:
            self._save()
        return new_entities, new_correlations

    def entities(self) -> list[Entity]:
        return list(self._entities.values())

    def get_entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def correlations(self) -> list[Correlation]:
        return list(self._correlations.values())

    def _save(self) -> None:
        (self.dir / "entities.json").write_text(
            json.dumps([e.to_dict() for e in self._entities.values()], indent=2)
        )
        (self.dir / "correlations.json").write_text(
            json.dumps([c.to_dict() for c in self._correlations.values()], indent=2)
        )

    def _load(self) -> None:
        ent_path = self.dir / "entities.json"
        if ent_path.exists():
            max_num = 0
            for d in json.loads(ent_path.read_text()):
                entity = Entity.from_dict(d)
                self._entities[entity.entity_id] = entity
                self._entity_by_key[(entity.entity_type, entity.value)] = entity.entity_id
                try:
                    max_num = max(max_num, int(entity.entity_id.split("-")[1]))
                except (IndexError, ValueError):
                    pass
            self._entity_counter = itertools.count(max_num + 1)

        corr_path = self.dir / "correlations.json"
        if corr_path.exists():
            for d in json.loads(corr_path.read_text()):
                corr = Correlation.from_dict(d)
                self._correlations[corr.correlation_id] = corr
