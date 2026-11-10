"""One CBOM and one score across many repositories."""

from __future__ import annotations

import json
from pathlib import Path


def merge_cboms(paths: list[Path]) -> dict:
    components = []
    for path in paths:
        bom = json.loads(path.read_text())
        repo = path.parent.name
        for c in bom.get("components", []):
            c = dict(c)
            c["name"] = f"{repo}:{c.get('name', 'unknown')}"
            components.append(c)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components,
        "metadata": {"component": {"name": "org-inventory", "type": "application"}},
    }


def org_score(bom: dict) -> dict:
    n = len(bom.get("components", []))
    return {"repositories": len({c["name"].split(":")[0] for c in bom.get("components", [])}), "components": n}
