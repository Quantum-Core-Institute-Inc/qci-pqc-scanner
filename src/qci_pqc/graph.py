"""Link a finding to the library and the app that uses it."""

from __future__ import annotations

from pathlib import Path

from .models import Finding


def link(findings: list[Finding], root: Path) -> list[dict]:
    app = root.name
    edges = []
    for f in findings:
        edges.append({
            "finding": f.family,
            "path": f.evidence_path,
            "app": app,
            "library": f.family if f.source_scanner == "qci-deps" else "",
            "implemented_by": f.parameter_set or "",
        })
    return edges
