"""Source and artifact scores are never blended."""

from __future__ import annotations

from .models import Finding


def split_scores(findings: list[Finding]) -> dict:
    source = [f for f in findings if f.source_scanner != "qci-artifact"]
    artifact = [f for f in findings if f.source_scanner == "qci-artifact"]
    return {
        "source": {"count": len(source)},
        "artifact": {"count": len(artifact)},
        "blended": False,
    }
