"""Reconcile a scan with a supplier CycloneDX CBOM."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def _names(cbom: dict) -> set[str]:
    out = set()
    for c in cbom.get("components", []):
        name = (c.get("name") or "").strip()
        if name:
            out.add(name.upper())
        crypto = c.get("cryptoProperties") or {}
        alg = (crypto.get("algorithmProperties") or {}).get("primitive") or ""
        if alg:
            out.add(str(alg).upper())
    return out


def reconcile(findings: list[Finding], supplier: Path) -> dict:
    cbom = json.loads(supplier.read_text())
    theirs = _names(cbom)
    ours = {f.family.upper() for f in findings if f.family}
    return {
        "supplier": supplier.name,
        "in_both": sorted(ours & theirs),
        "only_in_supplier": sorted(theirs - ours),
        "only_in_scan": sorted(ours - theirs),
    }
