"""Scan compiled artifacts for cryptographic indicators.

JARs, .class files, and selected binaries. Strings only. No unpacking
of packed or obfuscated code.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from .models import Finding, QuantumStatus

ARTIFACT_SUFFIXES = {".jar", ".class", ".war", ".ear"}
STRINGS = [
    (r"AES/GCM|AES/CBC|AES/ECB", "AES", QuantumStatus.SAFE_SYMMETRIC, "cipher"),
    (r"RSA/ECB|SHA256withRSA", "RSA", QuantumStatus.VULNERABLE, "sign"),
    (r"ML-KEM|ML-DSA", "ML-KEM", QuantumStatus.PQC, "kem"),
]


def scan_artifacts(root: Path) -> list[Finding]:
    findings = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in ARTIFACT_SUFFIXES:
            continue
        try:
            data = path.read_bytes()
        except Exception:
            continue
        if path.suffix.lower() == ".jar" and zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path) as zf:
                    data = b" ".join(zf.read(n) for n in zf.namelist() if n.endswith(".class"))
            except Exception:
                pass
        text = data.decode("latin-1", errors="ignore")
        rel = str(path.relative_to(root))
        for pat, fam, status, role in STRINGS:
            if re.search(pat, text):
                findings.append(Finding(
                    id=f"ART-{fam}-{path.name}",
                    evidence_path=rel,
                    evidence_line=0,
                    evidence_snippet=f"artifact:{path.name}",
                    family=fam,
                    quantum_status=status,
                    role=role,
                    source_scanner="qci-artifact",
                    confidence=0.6,
                    notes="Found in a compiled artifact, not in source.",
                ))
    return findings
