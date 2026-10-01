"""CLI commands for the investigation platform (Cypher 2.0).

Kept in its own module, separate from the CTF-era commands in
cli/main.py, per §34's modularity preference — the two subsystems don't
need to know about each other, and neither had to be rewritten to add
the other. Every command here is a thin wrapper around InvestigationAPI
(the same logic the HTTP server uses), so behavior is identical whether
driven from the CLI or the API.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cypher.investigation.api import InvestigationAPI
from cypher.investigation.case import CaseNotFoundError, InvalidCaseIdError
from cypher.investigation.report import render_markdown


def _api(args: argparse.Namespace) -> InvestigationAPI:
    root = Path(getattr(args, "cases_dir", None) or "./cases")
    return InvestigationAPI(root, sandbox_policy=getattr(args, "sandbox_policy", "competition"))


def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2))


def cmd_investigation_create(args: argparse.Namespace) -> int:
    api = _api(args)
    case = api.create_investigation(args.name, args.description or "")
    print(f"Created investigation: {case['case_id']} — {case['name']}")
    return 0


def cmd_investigation_list(args: argparse.Namespace) -> int:
    api = _api(args)
    cases = api.list_investigations()
    if not cases:
        print("No investigations yet. Create one with: cypher investigation create <name>")
        return 0
    for c in cases:
        print(f"{c['case_id']}  [{c['status']}]  {c['name']}")
    return 0


def cmd_investigation_show(args: argparse.Namespace) -> int:
    api = _api(args)
    try:
        _print_json(api.get_investigation(args.investigation_id))
    except (CaseNotFoundError, InvalidCaseIdError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_evidence_add(args: argparse.Namespace) -> int:
    api = _api(args)
    try:
        item = api.add_evidence(args.investigation_id, args.path)
    except (CaseNotFoundError, InvalidCaseIdError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Registered {item['evidence_id']}: {item['original_name']} (sha256 {item['sha256'][:16]}...)")
    return 0


def cmd_evidence_list(args: argparse.Namespace) -> int:
    api = _api(args)
    try:
        items = api.list_evidence(args.investigation_id)
    except (CaseNotFoundError, InvalidCaseIdError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if not items:
        print("No evidence yet. Add evidence to begin analysis.")
        return 0
    for e in items:
        print(f"{e['evidence_id']}  {e['original_name']}  ({e['mime_type']}, {e['analysis_state']})")
    return 0


def cmd_analysis_run(args: argparse.Namespace) -> int:
    api = _api(args)
    try:
        result = api.run_analysis(args.investigation_id, args.evidence_id, args.tool)
    except (CaseNotFoundError, InvalidCaseIdError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Status: {result['status']}")
    if result.get("observations_created"):
        print(f"{len(result['observations_created'])} observation(s) extracted.")
    return 0 if result.get("ok") else 1


def cmd_analysis_status(args: argparse.Namespace) -> int:
    api = _api(args)
    try:
        results = api.list_analysis_results(args.investigation_id)
    except (CaseNotFoundError, InvalidCaseIdError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if not results:
        print("No analysis has been run yet.")
        return 0
    for r in results:
        print(f"{r['id']}  {r['source_tool']} on {r['input_ref']}  — {r['summary']}")
    return 0


def cmd_observations_list(args: argparse.Namespace) -> int:
    api = _api(args)
    items = api.list_observations(args.investigation_id)
    if not items:
        print("No observations extracted yet.")
        return 0
    for o in items:
        print(f"{o['observation_id']}  [{o['type']}]  {o['value']}  (from {o['source_result_id']})")
    return 0


def cmd_correlations_list(args: argparse.Namespace) -> int:
    api = _api(args)
    items = api.list_correlations(args.investigation_id)
    if not items:
        print("No correlations identified yet.")
        return 0
    for c in items:
        print(f"{c['correlation_id']}  ({c['relationship']})  {c['reasoning']}")
    return 0


def cmd_findings_list(args: argparse.Namespace) -> int:
    api = _api(args)
    items = api.list_findings(args.investigation_id)
    if not items:
        print("No findings yet.")
        return 0
    for f in items:
        print(f"{f['finding_id']}  [{f['severity']}, {f['review_state']}]  {f['title']}")
    return 0


def cmd_finding_show(args: argparse.Namespace) -> int:
    api = _api(args)
    findings = api.list_findings(args.investigation_id)
    match = next((f for f in findings if f["finding_id"] == args.finding_id), None)
    if match is None:
        print(f"No such finding: {args.finding_id}", file=sys.stderr)
        return 1
    _print_json(match)
    return 0


def cmd_finding_decide(args: argparse.Namespace) -> int:
    api = _api(args)
    try:
        finding = api.decide_finding(args.investigation_id, args.finding_id, args.decision, args.note)
    except (CaseNotFoundError, InvalidCaseIdError, KeyError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"{finding['finding_id']}: {finding['review_state']}")
    return 0


def cmd_ai_analysis_run(args: argparse.Namespace) -> int:
    api = _api(args)
    if args.provider == "mock":
        from cypher.ai.mock import MockProvider
        api.ai_provider = MockProvider()
    try:
        result = api.run_ai_analysis(args.investigation_id)
    except (CaseNotFoundError, InvalidCaseIdError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"{len(result['accepted'])} finding(s) proposed, {len(result['rejected'])} rejected.")
    for r in result["rejected"]:
        print(f"  rejected: {r['reason']}")
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    import datetime

    api = _api(args)
    events = api.list_timeline(args.investigation_id)
    if not events:
        print("No timeline events yet.")
        return 0
    for e in events:
        ts = datetime.datetime.fromtimestamp(e["timestamp"]).strftime("%H:%M:%S")
        print(f"{ts}  {e['description']}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    api = _api(args)
    try:
        report = api.get_report(args.investigation_id)
    except (CaseNotFoundError, InvalidCaseIdError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if args.format == "markdown":
        print(render_markdown(report))
    else:
        _print_json(report)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from cypher.investigation.api import _BUNDLED_FRONTEND_DIR, run_server

    root = Path(getattr(args, "cases_dir", None) or "./cases")
    static = _BUNDLED_FRONTEND_DIR if _BUNDLED_FRONTEND_DIR.exists() else None
    server = run_server(root, host=args.host, port=args.port, static_dir=static)
    print(f"Cypher Investigation API listening on http://{args.host}:{args.port} (cases: {root.resolve()})")
    if static:
        print(f"Open http://{args.host}:{args.port}/ in a browser for the web UI.")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def add_investigation_subcommands(sub) -> None:
    """Registers all investigation-platform subcommands onto an existing
    argparse subparsers object, alongside the CTF-era solve/inspect/
    doctor/benchmark commands.
    """
    def add_common(p):
        p.add_argument("--cases-dir", help="Cases directory (default: ./cases)")

    inv = sub.add_parser("investigation", help="Investigation case management")
    inv_sub = inv.add_subparsers(dest="investigation_command", required=True)

    inv_create = inv_sub.add_parser("create", help="Create a new investigation")
    inv_create.add_argument("name")
    inv_create.add_argument("--description", default="")
    add_common(inv_create)
    inv_create.set_defaults(func=cmd_investigation_create)

    inv_list = inv_sub.add_parser("list", help="List investigations")
    add_common(inv_list)
    inv_list.set_defaults(func=cmd_investigation_list)

    inv_show = inv_sub.add_parser("show", help="Show investigation details")
    inv_show.add_argument("investigation_id")
    add_common(inv_show)
    inv_show.set_defaults(func=cmd_investigation_show)

    ev = sub.add_parser("evidence", help="Evidence management")
    ev_sub = ev.add_subparsers(dest="evidence_command", required=True)
    ev_add = ev_sub.add_parser("add", help="Add evidence to an investigation")
    ev_add.add_argument("investigation_id")
    ev_add.add_argument("path")
    add_common(ev_add)
    ev_add.set_defaults(func=cmd_evidence_add)
    ev_list = ev_sub.add_parser("list", help="List evidence")
    ev_list.add_argument("investigation_id")
    add_common(ev_list)
    ev_list.set_defaults(func=cmd_evidence_list)

    an = sub.add_parser("analysis", help="Run/inspect deterministic analysis")
    an_sub = an.add_subparsers(dest="analysis_command", required=True)
    an_run = an_sub.add_parser("run", help="Run a tool against evidence")
    an_run.add_argument("investigation_id")
    an_run.add_argument("evidence_id")
    an_run.add_argument("tool")
    add_common(an_run)
    an_run.set_defaults(func=cmd_analysis_run)
    an_status = an_sub.add_parser("status", help="List analysis results so far")
    an_status.add_argument("investigation_id")
    add_common(an_status)
    an_status.set_defaults(func=cmd_analysis_status)

    obs = sub.add_parser("observations", help="Observation management")
    obs_sub = obs.add_subparsers(dest="observations_command", required=True)
    obs_list = obs_sub.add_parser("list", help="List observations")
    obs_list.add_argument("investigation_id")
    add_common(obs_list)
    obs_list.set_defaults(func=cmd_observations_list)

    corr = sub.add_parser("correlations", help="Correlation management")
    corr_sub = corr.add_subparsers(dest="correlations_command", required=True)
    corr_list = corr_sub.add_parser("list", help="List correlations")
    corr_list.add_argument("investigation_id")
    add_common(corr_list)
    corr_list.set_defaults(func=cmd_correlations_list)

    find = sub.add_parser("findings", help="Findings management")
    find_sub = find.add_subparsers(dest="findings_command", required=True)
    find_list = find_sub.add_parser("list", help="List findings")
    find_list.add_argument("investigation_id")
    add_common(find_list)
    find_list.set_defaults(func=cmd_findings_list)

    finding = sub.add_parser("finding", help="Single-finding operations")
    finding_sub = finding.add_subparsers(dest="finding_command", required=True)
    finding_show = finding_sub.add_parser("show", help="Show one finding")
    finding_show.add_argument("investigation_id")
    finding_show.add_argument("finding_id")
    add_common(finding_show)
    finding_show.set_defaults(func=cmd_finding_show)
    finding_decide = finding_sub.add_parser("decide", help="Confirm/reject/flag a finding")
    finding_decide.add_argument("investigation_id")
    finding_decide.add_argument("finding_id")
    finding_decide.add_argument("decision", choices=["confirm", "reject", "review"])
    finding_decide.add_argument("--note")
    add_common(finding_decide)
    finding_decide.set_defaults(func=cmd_finding_decide)

    ai = sub.add_parser("ai-analysis", help="Run the AI Analyst against an investigation")
    ai.add_argument("investigation_id")
    ai.add_argument("--provider", choices=["ollama", "mock"], default="ollama")
    add_common(ai)
    ai.set_defaults(func=cmd_ai_analysis_run)

    timeline = sub.add_parser("timeline", help="Show investigation timeline")
    timeline.add_argument("investigation_id")
    add_common(timeline)
    timeline.set_defaults(func=cmd_timeline)

    report = sub.add_parser("report", help="Generate an investigation report")
    report.add_argument("investigation_id")
    report.add_argument("--format", choices=["json", "markdown"], default="markdown")
    add_common(report)
    report.set_defaults(func=cmd_report)

    serve = sub.add_parser("serve", help="Start the investigation HTTP API server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    add_common(serve)
    serve.set_defaults(func=cmd_serve)
