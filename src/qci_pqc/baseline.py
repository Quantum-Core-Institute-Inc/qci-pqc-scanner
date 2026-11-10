"""Stable baseline diff: what changed since last quarter."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def key(f: Finding) -> str:
    return f"{f.family}|{Path(f.evidence_path).name}|{f.parameter_set}"


def load_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text())
    return set(data.get("keys", []))


def diff(findings: list[Finding], baseline: set[str]) -> dict:
    """1.x baselines still load. Artifact findings are new, not regressions."""
    findings = [f for f in findings if f.source_scanner != "qci-artifact"]

    current = {key(f) for f in findings}
    return {
        "new": sorted(current - baseline),
        "resolved": sorted(baseline - current),
        "unchanged": sorted(current & baseline),
    }


def save_baseline(findings: list[Finding], path: Path) -> None:
    path.write_text(json.dumps({"keys": sorted({key(f) for f in findings})}, indent=2) + "\n")
