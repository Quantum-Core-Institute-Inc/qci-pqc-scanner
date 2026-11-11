"""Source and artifact scores are never blended."""

from __future__ import annotations

from .models import Finding


def split_scores(findings: list[Finding]) -> dict:
    source = [f for f in findings if f.source_scanner != "qci-artifact"]
    artifact = [f for f in findings if f.source_scanner == "qci-artifact"]
    named = sum(1 for f in artifact if "!" in (f.evidence_snippet or "") or "." in (f.evidence_snippet or ""))
    with_param = sum(1 for f in artifact if f.parameter_set)
    return {
        "source": {"count": len(source)},
        "artifact": {
            "count": len(artifact),
            "named_class": named,
            "with_parameter": with_param,
            "families": sorted({f.family for f in artifact}),
        },
        "blended": False,
    }
