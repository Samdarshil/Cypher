"""Analysis orchestration — the §3 workflow's "Deterministic Analysis /
Store Raw Results" step. Deliberately thin: it reuses ToolExecutor and
EvidenceStore exactly as they already exist (proven, tested code from
the CTF-era build), and just wires evidence -> tool -> result -> timeline
together with the new case/evidence identifiers.

AI interpretation and structured Finding generation are the NEXT layer
(not built in this pass — see the audit note in the final report) so
that this layer stays independently useful even if Ollama is
unavailable, per spec section 3: "The system must work even if the AI is
unavailable."
"""
from __future__ import annotations

from pathlib import Path

from cypher.evidence.models import EvidenceStore
from cypher.investigation.evidence import AnalysisState, EvidenceRegistry
from cypher.investigation.timeline import Timeline
from cypher.tools.executor import ToolExecutor, ToolResult, ToolValidationError
from cypher.tools.registry import ToolRegistry


class AnalysisOrchestrator:
    def __init__(
        self,
        case_workspace: Path,
        evidence_registry: EvidenceRegistry,
        registry: ToolRegistry,
        timeline: Timeline,
        sandbox_policy: str = "competition",
    ) -> None:
        self.case_workspace = Path(case_workspace)
        self.evidence_registry = evidence_registry
        self.registry = registry
        self.timeline = timeline
        self.results = EvidenceStore(self.case_workspace / "results")
        self.executor = ToolExecutor(registry, self.case_workspace, sandbox_policy=sandbox_policy)

    def analyze(self, evidence_id: str, tool_name: str, extra_args: list[str] | None = None) -> ToolResult | None:
        """Run one tool against one evidence item, storing the raw result
        and recording a timeline event either way (success or failure —
        a failure is still real information about the investigation).
        """
        item = self.evidence_registry.get(evidence_id)
        if item is None:
            raise ValueError(f"No such evidence: {evidence_id!r}")

        self.evidence_registry.mark_state(evidence_id, AnalysisState.ANALYZING)
        rel_input = str(item.stored_path.relative_to(self.case_workspace))

        try:
            result = self.executor.execute(tool_name, rel_input, extra_args)
        except ToolValidationError as exc:
            self.evidence_registry.mark_state(evidence_id, AnalysisState.ERROR)
            self.timeline.record(
                f"{tool_name} on {item.original_name} ({evidence_id}) failed validation: {exc}",
                source_ref=evidence_id,
            )
            return None

        stored = self.results.add(
            source_tool=tool_name,
            input_ref=evidence_id,
            summary=f"{tool_name} on {item.original_name}: exit={result.exit_code}, sandbox={result.sandbox_mode}",
            raw_output=result.stdout + "\n" + result.stderr,
            relevance=0.5,  # neutral -- this layer doesn't score relevance; AI interpretation would
        )
        self.evidence_registry.attach_result(evidence_id, stored.id)
        self.timeline.record(
            f"Analyzed {item.original_name} ({evidence_id}) with {tool_name} -> {stored.id}",
            source_ref=stored.id,
        )
        return result
