"""CLI entry point for the QCI crypto inventory."""

import json
import sys
from pathlib import Path

import click

from . import __version__
from .models import Inventory
from .report import write_reports
from .adapters import get_adapter
from .dedupe import deduplicate
from .enrich import enrich_findings
from .compliance import (
    apply_ignore, diff_baseline, evidence_manifest, export_tickets,
    load_baseline, load_ignore, save_baseline as write_baseline,
)
from .calibrate import calibrate as run_calibrate
from .scoring import compute_readiness, score_scanner
from .scoresplit import split_scores
from .graph import link
from .policy import evaluate_policy, load_accepted_risks, load_policy


@click.group()
@click.version_option(__version__)
def cli():
    """QCI crypto inventory. Source, config, and artifacts. Exports a CycloneDX CBOM."""
    pass


@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind address (default localhost)")
@click.option("--port", default=8080, type=int, help="Port")
@click.option("--out", default="qci-pqc-web-out", help="Output directory for web scans")
def serve(host: str, port: int, out: str):
    """Start the local web UI (same engine as the CLI)."""
    from .web import serve as run_serve
    run_serve(host=host, port=port, out=out)


@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--out", "-o", default="qci-pqc-out", help="Output directory")
@click.option("--adapter", "-a", default="internal", help="Scanner adapter (internal, cryptoscan, qscan, semgrep, or comma-separated list)")
@click.option("--fail-on", type=click.Choice(["vulnerable", "weak", "none"]), default="none",
              help="Exit with code 1 if findings of this severity exist")
@click.option("--no-dedupe", is_flag=True, help="Disable deduplication")
@click.option("--ignore", type=click.Path(path_type=Path), help="Ignore file (family|file|line)")
@click.option("--baseline", type=click.Path(path_type=Path), help="Baseline JSON for diff")
@click.option("--save-baseline", type=click.Path(path_type=Path), help="Write current findings as baseline")
@click.option("--tickets", is_flag=True, help="Export ticket JSON for GRC/ticketing")
@click.option("--metadata", type=click.Path(path_type=Path), help="Optional metadata JSON (owner, system, data_lifetime)")
@click.option("--calibrate", is_flag=True, help="Print precision/recall metrics and exit (no full report)")
@click.option("--verbose", "-v", is_flag=True, help="Print each finding and extra details")
@click.option("--json", "json_out", is_flag=True, help="Print summary as JSON to stdout")
@click.option("--reproducible", is_flag=True, help="Stable output: no timestamps, sorted findings, content-addressed IDs")
@click.option("--policy", type=click.Path(path_type=Path), help="Policy JSON (fail_on, require_acceptance_for)")
@click.option("--accepted-risks", type=click.Path(path_type=Path), help="Accepted-risk JSON with justifications")
def scan(path: Path, out: str, adapter: str, fail_on: str, no_dedupe: bool,
         ignore: Path, baseline: Path, save_baseline: Path, tickets: bool, metadata: Path,
         calibrate: bool, verbose: bool, json_out: bool, reproducible: bool,
         policy: Path, accepted_risks: Path):
    """Scan a directory for cryptographic usage and produce readiness reports."""
    def status(message):
        click.echo(message, err=json_out)

    adapters = [a.strip() for a in adapter.split(",") if a.strip()]
    status(f"Scanning {path} with adapter(s): {', '.join(adapters)} ...")

    all_findings = []
    scanners_used = []

    for name in adapters:
        try:
            scanner = get_adapter(name)
            if not scanner.available():
                click.echo(f"Adapter '{name}' not available, skipping.", err=True)
                continue
            findings = scanner.scan(path)
            all_findings.extend(findings)
            scanners_used.append(scanner.name)
            status(f"  {scanner.name}: {len(findings)} raw findings")
            if verbose:
                for f in findings:
                    status(f"    [{f.quantum_status.value:12}] {f.family:16} {f.evidence_path}:{f.evidence_line}")
        except Exception as e:
            click.echo(f"Adapter '{name}' failed: {e}", err=True)

    if not all_findings and not scanners_used:
        # full fallback
        click.echo("No adapters succeeded. Falling back to internal.", err=True)
        scanner = get_adapter("internal")
        all_findings = scanner.scan(path)
        scanners_used = [scanner.name]

    if not no_dedupe:
        before = len(all_findings)
        all_findings = deduplicate(all_findings)
        status(f"Deduplicated: {before} → {len(all_findings)} findings")
    parts = split_scores(all_findings)
    status(f"Source findings: {parts['source']['count']}")
    status(f"Artifact findings: {parts['artifact']['count']}")
    status("Scores are not blended.")
    edges = link(all_findings, path)
    (Path(out) / "graph.json").write_text(json.dumps(edges, indent=2) + "\n")
    status(f"Dependency graph: {len(edges)} edges")

    # Calibration-only mode: print metrics and exit
    if calibrate:
        metrics = run_calibrate(path)
        if json_out:
            click.echo(json.dumps(metrics, indent=2))
        else:
            click.echo("Calibration metrics")
            click.echo(f"  Precision:       {metrics['precision']}")
            click.echo(f"  Recall:          {metrics['recall']}")
            click.echo(f"  True positives:  {metrics['true_positives']}")
            click.echo(f"  False positives: {metrics['false_positives']}")
            click.echo(f"  False negatives: {metrics['false_negatives']}")
            click.echo(f"  Expected:        {metrics['expected_positive']}")
            click.echo(f"  Total findings:  {metrics['total_findings']}")
        return

    all_findings = enrich_findings(all_findings)

    if reproducible:
        all_findings.sort(key=lambda f: (f.evidence_path, f.evidence_line or 0, f.family))
        for i, f in enumerate(all_findings, 1):
            f.id = f"QCI-{i:04d}"

    # Ignore
    ignored = []
    if ignore:
        all_findings, ignored = apply_ignore(all_findings, load_ignore(ignore))
        status(f"Ignored: {len(ignored)} findings")

    # Baseline diff
    baseline_diff = None
    if baseline:
        baseline_diff = diff_baseline(all_findings, load_baseline(baseline))
        status(f"Baseline diff: +{len(baseline_diff['new'])} new, -{len(baseline_diff['resolved'])} resolved")

    if save_baseline:
        write_baseline(all_findings, save_baseline)
        status(f"Baseline saved to {save_baseline}")

    # Optional metadata tagging
    if metadata and metadata.exists():
        meta = json.loads(metadata.read_text())
        for f in all_findings:
            f.notes = (f.notes + " | " if f.notes else "") + f"owner={meta.get('owner','')} system={meta.get('system','')} lifetime={meta.get('data_lifetime','')}"
            f.lifetime = meta.get("data_lifetime", "")
            f.owner = meta.get("owner", "")
            f.system = meta.get("system", "")

    inv = Inventory(
        project=path.name,
        scanners_used=scanners_used,
        findings=all_findings,
    )
    inv.reproducible = reproducible
    inv.coverage = score_scanner(all_findings)
    inv.readiness_score, inv.priority_findings, inv.readiness_breakdown = compute_readiness(all_findings)
    # Calibration (only meaningful when scanning the test corpus; harmless otherwise)
    try:
        inv.calibration = run_calibrate(path)
    except Exception:
        inv.calibration = {}

    # Policy evaluation (before reports so HTML can show it)
    if policy or accepted_risks:
        pol = load_policy(policy)
        acc = load_accepted_risks(accepted_risks)
        inv.policy_result = evaluate_policy(all_findings, pol, acc)

    out_path = Path(out)
    write_reports(inv, out_path)

    # Extra compliance artifacts
    findings_export = [
        {
            "id": f.id, "family": f.family, "status": f.quantum_status.value,
            "path": f.evidence_path, "line": f.evidence_line,
            "priority": getattr(f, "priority_score", 0),
            "recommendation": getattr(f, "recommendation", ""),
            "timeline": getattr(f, "timeline_flags", []),
        }
        for f in all_findings
    ]
    (out_path / "findings.json").write_text(json.dumps(findings_export, indent=2))

    summary = {
        "project": inv.project,
        "findings": len(all_findings),
        "readiness_score": inv.readiness_score,
        "scanners": scanners_used,
        "ruleset_hash": __import__("qci_pqc.compliance", fromlist=["ruleset_hash"]).ruleset_hash(),
        "reproducible": reproducible,
    }
    evidence_manifest(out_path, summary, reproducible=reproducible)

    if tickets:
        n = export_tickets(all_findings, out_path / "tickets.json")
        status(f"Exported {n} tickets to {out_path}/tickets.json")

    summary = {
        "project": inv.project,
        "findings": len(all_findings),
        "readiness_score": inv.readiness_score,
        "breakdown": inv.readiness_breakdown,
        "scanners": scanners_used,
        "ignored": len(ignored),
        "baseline_diff": baseline_diff,
        "outputs": {
            "report": str(out_path / "report.html"),
            "cbom": str(out_path / "cbom.json"),
            "sarif": str(out_path / "results.sarif"),
        },
    }

    if json_out:
        click.echo(json.dumps(summary, indent=2))
    else:
        click.echo(f"Findings: {len(all_findings)}")
        click.echo(f"Readiness score: {inv.readiness_score}/100")
        if verbose and inv.readiness_breakdown:
            b = inv.readiness_breakdown
            click.echo(f"  Vulnerable: {b.get('vulnerable_count', 0)}  Weak: {b.get('weak_count', 0)}  PQC: {b.get('pqc_count', 0)}")
            click.echo(f"  Formula: {b.get('formula', '')}")
        q = inv.coverage.get("quantum")
        if q:
            click.echo(f"Quantum form recognition: {q.recognised}/{q.total}")
        click.echo(f"Reports written to {out_path}/")
        click.echo(f"  - {out_path}/report.html")
        click.echo(f"  - {out_path}/cbom.json")
        click.echo(f"  - {out_path}/results.sarif")
        click.echo(f"  - {out_path}/findings.json")
        click.echo(f"  - {out_path}/evidence-manifest.json")

    # Policy artifacts and gate
    if inv.policy_result:
        (out_path / "policy-result.json").write_text(json.dumps(inv.policy_result, indent=2))
        n_viol = len(inv.policy_result.get("violations", []))
        n_waived = len(inv.policy_result.get("waived", []))
        click.echo(f"Policy: {n_viol} violations, {n_waived} waived")
        if not inv.policy_result.get("passed", True):
            click.echo(f"Policy violations: {n_viol}", err=True)
            if fail_on != "none":
                sys.exit(1)

    if fail_on == "vulnerable" and any(f.quantum_status.value == "vulnerable" for f in all_findings):
        click.echo("Failing due to Shor-vulnerable findings.", err=True)
        sys.exit(1)
    if fail_on == "weak" and any(f.classical_weak or f.quantum_status.value == "weak" for f in all_findings):
        click.echo("Failing due to weak findings.", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
