"""pql-cli: the v0.9 operator CLI for QCI PQC scans."""

import json
import sys
from pathlib import Path

import click

from . import __version__
from .baseline import diff, load_baseline, save_baseline
from .cli import scan as scan_cmd
from .policy import evaluate_policy, load_accepted_risks, load_policy


@click.group()
@click.version_option(__version__, prog_name="pql-cli")
def pql():
    """PQL: scan, diff, and gate a repository for post-quantum readiness."""
    pass


@pql.command("scan")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--out", "-o", default="pql-out", help="Output directory")
@click.option("--save-baseline", type=click.Path(path_type=Path), help="Write a baseline after the scan")
@click.option("--json", "json_out", is_flag=True, help="Print the summary as JSON")
def scan(path: Path, out: str, save_baseline: Path, json_out: bool):
    """Scan a repository and write the inventory and report."""
    from .scanner import scan_path
    from .baseline import save_baseline as write_baseline
    findings = list(scan_path(path))
    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)
    click.echo(f"Findings: {len(findings)}")
    if save_baseline:
        write_baseline(findings, save_baseline)
        click.echo(f"Baseline saved to {save_baseline}")


@pql.command("diff")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--baseline", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--json", "json_out", is_flag=True)
def diff_cmd(path: Path, baseline: Path, json_out: bool):
    """Show what changed since the baseline."""
    from .scanner import scan_path
    findings = list(scan_path(path))
    result = diff(findings, load_baseline(baseline))
    if json_out:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"New: {len(result['new'])}")
        for item in result["new"]:
            click.echo(f"  + {item}")
        click.echo(f"Resolved: {len(result['resolved'])}")
        for item in result["resolved"]:
            click.echo(f"  - {item}")
    sys.exit(1 if result["new"] else 0)


@pql.command("gate")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--policy", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--accepted-risks", type=click.Path(exists=True, path_type=Path))
def gate(path: Path, policy: Path, accepted_risks: Path):
    """Exit 1 if the policy fails."""
    from .scanner import scan_path
    findings = list(scan_path(path))
    accepted = load_accepted_risks(accepted_risks) if accepted_risks else {}
    result = evaluate_policy(findings, load_policy(policy), accepted)
    click.echo(f"Violations: {len(result['violations'])}")
    click.echo(f"Waived: {len(result['waived'])}")
    for v in result["violations"]:
        click.echo(f"  {v['family']} {v['path']}:{v['line']}")
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    pql()


@pql.command("org")
@click.argument("cboms", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--out", default="org-cbom.json")
def org(cboms, out):
    """Merge repository CBOMs into one inventory."""
    from .org import merge_cboms, org_score
    bom = merge_cboms(list(cboms))
    Path(out).write_text(json.dumps(bom, indent=2) + "\n")
    click.echo(json.dumps(org_score(bom)))


@pql.command("trend")
@click.option("--file", "path", default="trend.json", type=click.Path(path_type=Path))
@click.option("--score", type=float, required=True)
@click.option("--ticket-ready", type=float, required=True)
@click.option("--new", "new_n", type=int, default=0)
@click.option("--resolved", type=int, default=0)
def trend(path, score, ticket_ready, new_n, resolved):
    """Append a score point."""
    from .trend import append, summary
    append(path, score, ticket_ready, new_n, resolved)
    click.echo(json.dumps(summary(path)))
