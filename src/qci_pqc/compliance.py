"""Baseline, ignore, history, and evidence helpers for compliance workflows."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding


def load_ignore(path: Path | None) -> set[str]:
    """Load ignore keys (family|filename|line or family|filename)."""
    if not path or not path.exists():
        return set()
    keys = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            keys.add(line)
    return keys


def finding_key(f: Finding) -> str:
    return f"{f.family}|{Path(f.evidence_path).name}|{f.evidence_line or 0}"


def apply_ignore(findings: list[Finding], ignore: set[str]) -> tuple[list[Finding], list[Finding]]:
    kept, ignored = [], []
    for f in findings:
        key = finding_key(f)
        short = f"{f.family}|{Path(f.evidence_path).name}"
        if key in ignore or short in ignore:
            ignored.append(f)
        else:
            kept.append(f)
    return kept, ignored


def save_baseline(findings: list[Finding], path: Path):
    data = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "keys": [finding_key(f) for f in findings],
    }
    path.write_text(json.dumps(data, indent=2))


def load_baseline(path: Path | None) -> set[str]:
    if not path or not path.exists():
        return set()
    data = json.loads(path.read_text())
    return set(data.get("keys", []))


def diff_baseline(findings: list[Finding], baseline: set[str]) -> dict:
    current = {finding_key(f) for f in findings}
    return {
        "new": sorted(current - baseline),
        "resolved": sorted(baseline - current),
        "unchanged": sorted(current & baseline),
    }


def ruleset_hash() -> str:
    """SHA-256 of the internal pattern definitions and Semgrep rules."""
    from .scanner import PATTERNS
    import hashlib
    payload = json.dumps(
        [(p[0], p[1], p[2].value if hasattr(p[2], "value") else str(p[2]), p[3], p[4]) for p in PATTERNS],
        sort_keys=True,
    )
    rules_path = Path(__file__).parent / "rules" / "crypto.yml"
    if rules_path.exists():
        payload += rules_path.read_text()
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def evidence_manifest(out_dir: Path, inv_summary: dict, reproducible: bool = False) -> dict:
    """Create an evidence manifest with file hashes and ruleset identity."""
    files = {}
    for name in ("report.html", "cbom.json", "results.sarif", "findings.json"):
        p = out_dir / name
        if p.exists():
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            files[name] = {"sha256": h, "size": p.stat().st_size}
    manifest = {
        "generated": None if reproducible else datetime.now(timezone.utc).isoformat(),
        "scanner_version": "0.5.0",
        "ruleset_hash": ruleset_hash(),
        "reproducible": reproducible,
        "summary": inv_summary,
        "files": files,
    }
    (out_dir / "evidence-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


def export_tickets(findings: list[Finding], path: Path):
    """Simple JSON export suitable for import into Jira/ServiceNow-style tools."""
    tickets = []
    for f in findings:
        if f.quantum_status.value not in ("vulnerable", "weak"):
            continue
        tickets.append({
            "summary": f"PQC: {f.family} ({f.quantum_status.value}) in {Path(f.evidence_path).name}",
            "description": f"{f.recommendation or f.notes}\nLocation: {f.evidence_path}:{f.evidence_line}\nTimeline: {'; '.join(f.timeline_flags)}",
            "priority": "High" if f.quantum_status.value == "vulnerable" else "Medium",
            "labels": ["pqc", f.quantum_status.value, f.family.lower()],
            "location": f"{f.evidence_path}:{f.evidence_line}",
        })
    path.write_text(json.dumps(tickets, indent=2))
    return len(tickets)
