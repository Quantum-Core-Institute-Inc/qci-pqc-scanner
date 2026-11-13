"""Deduplication of findings across scanners or within one scanner.

Merge rule:
- Same normalized family
- Same file path
- Line numbers within a small window (default ±3)

When merging:
- Keep the highest-confidence finding as primary
- Record all source scanners
- Prefer more specific quantum_status
"""

import re
from collections import defaultdict
from typing import Optional

from .models import Finding, QuantumStatus

# Higher number = preferred when statuses conflict
STATUS_PRIORITY = {
    QuantumStatus.VULNERABLE: 5,
    QuantumStatus.WEAK: 4,
    QuantumStatus.HYBRID: 3,
    QuantumStatus.PQC: 3,
    QuantumStatus.SAFE_SYMMETRIC: 2,
    QuantumStatus.UNKNOWN: 1,
}


def _normalize_family(family: str) -> str:
    f = family.lower().strip()
    # A cipher suite or a protocol version is its own thing: TLS_RSA_WITH_AES_128_CBC_SHA is not "rsa".
    if f.startswith(("tls_", "tls-", "ssl-")):
        return f
    # Collapse common variants
    replacements = {
        "rsa": "rsa",
        "ecdsa": "ecdsa",
        "ec": "ecdsa",
        "md5": "md5",
        "sha-1": "sha1",
        "sha1": "sha1",
        "sha-256": "sha256",
        "sha256": "sha256",
        "aes-ecb": "aes-ecb",
        "aes/ecb": "aes-ecb",
        "ml-kem": "ml-kem",
        "kyber": "ml-kem",
        "mlkem": "ml-kem",
    }
    for key, val in replacements.items():
        if key in f:
            return val
    return f


def _normalize_path(path: str) -> str:
    """Keep the relative path. Basename collapses main.go in two packages."""
    return path.replace("\\", "/").rstrip("/")


def _key(f: Finding, window: int) -> tuple:
    line_bucket = (f.evidence_line or 0) // (window * 2 + 1)
    # Artifacts have no line. The snippet names the class and method.
    site = f.evidence_snippet if (f.evidence_line or 0) == 0 else ""
    return (
        _normalize_family(f.family),
        _normalize_path(f.evidence_path),
        line_bucket,
        site,
    )


def _param_parts(f):
    p = (f.parameter_set or "").strip()
    if not p or p.upper() == (f.family or "").upper():
        return set()
    return {x for x in p.upper().split("-") if x}


def _richest_param(primary, group):
    mine = _param_parts(primary)
    best = max(group, key=lambda f: len(_param_parts(f)))
    theirs = _param_parts(best)
    if len(theirs) > len(mine) and mine <= theirs:
        return best.parameter_set
    return primary.parameter_set


def deduplicate(findings: list[Finding], window: int = 3) -> list[Finding]:
    """Return a deduplicated list of findings."""
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[_key(f, window)].append(f)

    result = []
    for group in groups.values():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Pick primary: highest confidence, then best status
        primary = max(
            group,
            key=lambda x: (
                x.confidence,
                STATUS_PRIORITY.get(x.quantum_status, 0),
            ),
        )

        # Merge metadata
        sources = sorted({f.source_scanner for f in group})
        best_status = max(
            (f.quantum_status for f in group),
            key=lambda s: STATUS_PRIORITY.get(s, 0),
        )
        snippets = [f.evidence_snippet for f in group if f.evidence_snippet]
        notes_parts = [f.notes for f in group if f.notes]

        merged = Finding(
            id=primary.id,
            evidence_path=primary.evidence_path,
            evidence_line=primary.evidence_line,
            evidence_snippet=primary.evidence_snippet or (snippets[0] if snippets else ""),
            family=primary.family,
            parameter_set=_richest_param(primary, group),
            role=primary.role or next((f.role for f in group if f.role), None),
            quantum_status=best_status,
            classical_weak=any(f.classical_weak for f in group),
            defect_cwe=primary.defect_cwe,
            source_scanner="+".join(sources),
            confidence=max(f.confidence for f in group),
            notes="; ".join(notes_parts) if notes_parts else f"Merged from {len(group)} scanners",
        )
        result.append(merged)

    # Stable sort by path then line
    result.sort(key=lambda f: (f.evidence_path, f.evidence_line or 0))
    return result
