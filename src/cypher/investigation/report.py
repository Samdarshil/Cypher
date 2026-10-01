"""Report generation (spec §29).

Deterministic: this module never calls an AIProvider and never invents
a conclusion. It only reorganizes and formats data that's already
persisted (evidence, observations, correlations, findings, timeline).
The AI's own words appear only inside a finding's `summary`/`reasoning`
fields, verbatim, clearly under an "AI INTERPRETATION" heading — never
rewritten or upgraded to sound more certain than the model stated it,
and never presented under "OBSERVED".

Section separation is structural, not just visual: `generate_report()`
returns a dict with the three-way split as top-level keys, so a
consumer (CLI renderer, API client, future frontend) cannot accidentally
merge "AI proposed X" with "X is true".
"""
from __future__ import annotations

from cypher.investigation.case import InvestigationCase
from cypher.investigation.correlation import CorrelationEngine
from cypher.investigation.evidence import EvidenceRegistry
from cypher.investigation.findings import FindingStore, ReviewState
from cypher.investigation.observation import ObservationStore
from cypher.investigation.timeline import Timeline


def generate_report(
    case: InvestigationCase,
    evidence_registry: EvidenceRegistry,
    observation_store: ObservationStore,
    correlation_engine: CorrelationEngine,
    finding_store: FindingStore,
    timeline: Timeline,
) -> dict:
    evidence = evidence_registry.all()
    observations = observation_store.all()
    entities = correlation_engine.entities()
    correlations = correlation_engine.correlations()
    all_findings = finding_store.all()
    events = timeline.all()

    ai_proposed = [f for f in all_findings if f.review_state == ReviewState.AI_PROPOSED]
    needs_review = [f for f in all_findings if f.review_state == ReviewState.NEEDS_REVIEW]
    confirmed = [f for f in all_findings if f.review_state == ReviewState.HUMAN_CONFIRMED]
    rejected = [f for f in all_findings if f.review_state == ReviewState.HUMAN_REJECTED]

    recommended_next_steps: list[str] = []
    if not evidence:
        recommended_next_steps.append("Add evidence to begin analysis.")
    elif not observations and not all_findings:
        recommended_next_steps.append("Run analysis tools against the registered evidence.")
    elif ai_proposed or needs_review:
        recommended_next_steps.append(
            f"{len(ai_proposed) + len(needs_review)} finding(s) awaiting human review."
        )
    # Deliberately no other fabricated suggestions -- if none of the
    # above apply, the list stays empty rather than inventing advice.

    return {
        "investigation": {
            "case_id": case.case_id,
            "name": case.name,
            "description": case.description,
            "status": case.status.value,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
        },
        "observed": {
            "evidence_inventory": [e.to_dict() for e in evidence],
            "observations": [o.to_dict() for o in observations],
            "entities": [e.to_dict() for e in entities],
            "correlations": [c.to_dict() for c in correlations],
            "timeline": [t.to_dict() for t in events],
        },
        "ai_interpretation": {
            "proposed_findings": [f.to_dict() for f in ai_proposed],
            "needs_review_findings": [f.to_dict() for f in needs_review],
        },
        "human_decisions": {
            "confirmed_findings": [f.to_dict() for f in confirmed],
            "rejected_findings": [f.to_dict() for f in rejected],
        },
        "recommended_next_steps": recommended_next_steps,
    }


def render_markdown(report: dict) -> str:
    inv = report["investigation"]
    obs = report["observed"]
    ai = report["ai_interpretation"]
    human = report["human_decisions"]

    lines = [
        f"# Investigation Report — {inv['name']}",
        "",
        f"**Case ID:** {inv['case_id']}  ",
        f"**Status:** {inv['status']}  ",
        f"**Description:** {inv['description'] or '(none provided)'}",
        "",
        "## Executive Summary",
        "",
        (
            f"{len(obs['evidence_inventory'])} evidence item(s), "
            f"{len(obs['observations'])} observation(s), "
            f"{len(obs['correlations'])} correlation(s), "
            f"{len(ai['proposed_findings']) + len(ai['needs_review_findings'])} AI-proposed finding(s) "
            f"({len(human['confirmed_findings'])} confirmed, {len(human['rejected_findings'])} rejected by a human)."
        ),
        "",
        "## Evidence Inventory (OBSERVED)",
        "",
    ]
    if obs["evidence_inventory"]:
        for e in obs["evidence_inventory"]:
            lines.append(f"- **{e['evidence_id']}** — {e['original_name']} "
                         f"({e['mime_type']}, {e['size_bytes']} bytes, sha256 `{e['sha256'][:16]}...`) "
                         f"— {e['analysis_state']}")
    else:
        lines.append("No evidence has been added to this investigation.")
    lines.append("")

    lines.append("## Observed Indicators (OBSERVED)")
    lines.append("")
    if obs["observations"]:
        for o in obs["observations"]:
            lines.append(f"- **{o['observation_id']}** [{o['type']}] `{o['value']}` (from {o['source_result_id']})")
    else:
        lines.append("No indicators have been extracted yet.")
    lines.append("")

    lines.append("## Correlations (OBSERVED)")
    lines.append("")
    if obs["correlations"]:
        for c in obs["correlations"]:
            lines.append(f"- **{c['correlation_id']}** ({c['relationship']}): {c['reasoning']}")
    else:
        lines.append("No correlations identified yet.")
    lines.append("")

    lines.append("## AI Interpretation — NOT confirmed facts")
    lines.append("")
    lines.append("_The following are AI-generated hypotheses awaiting human review. "
                  "They are not confirmed findings._")
    lines.append("")
    all_ai = ai["proposed_findings"] + ai["needs_review_findings"]
    if all_ai:
        for f in all_ai:
            lines.append(f"### {f['finding_id']} — {f['title']} [{f['severity']}, confidence {f['confidence']:.2f}]")
            lines.append(f"- Summary: {f['summary']}")
            lines.append(f"- Reasoning: {f['reasoning']}")
            lines.append(f"- Evidence: {', '.join(f['evidence_refs'] + f['tool_result_refs']) or '(none)'}")
            lines.append(f"- Status: {f['review_state']}")
            lines.append("")
    else:
        lines.append("No AI-proposed findings awaiting review.")
        lines.append("")

    lines.append("## Human-Confirmed Findings")
    lines.append("")
    if human["confirmed_findings"]:
        for f in human["confirmed_findings"]:
            lines.append(f"### {f['finding_id']} — {f['title']} [{f['severity']}]")
            lines.append(f"- Summary: {f['summary']}")
            lines.append(f"- Evidence: {', '.join(f['evidence_refs'] + f['tool_result_refs']) or '(none)'}")
            if f.get("analyst_note"):
                lines.append(f"- Analyst note: {f['analyst_note']}")
            lines.append("")
    else:
        lines.append("No findings have been confirmed by a human analyst.")
        lines.append("")

    lines.append("## Human-Rejected Findings")
    lines.append("")
    if human["rejected_findings"]:
        for f in human["rejected_findings"]:
            lines.append(f"- **{f['finding_id']}** — {f['title']}" + (f" ({f['analyst_note']})" if f.get("analyst_note") else ""))
    else:
        lines.append("No findings have been rejected.")
    lines.append("")

    lines.append("## Timeline")
    lines.append("")
    if obs["timeline"]:
        import datetime
        for t in obs["timeline"]:
            ts = datetime.datetime.fromtimestamp(t["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"- `{ts}` {t['description']}")
    else:
        lines.append("No timeline events recorded.")
    lines.append("")

    lines.append("## Recommended Next Steps")
    lines.append("")
    if report["recommended_next_steps"]:
        for step in report["recommended_next_steps"]:
            lines.append(f"- {step}")
    else:
        lines.append("None.")

    return "\n".join(lines)
