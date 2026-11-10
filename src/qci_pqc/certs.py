"""Basic X.509 / PEM certificate inspection (no external deps required for MVP)."""

import base64
import re
from pathlib import Path

from .models import Finding, QuantumStatus


def inspect_pem(path: Path, root: Path) -> list[Finding]:
    """Extract simple signals from PEM certificates and keys."""
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    if "-----BEGIN CERTIFICATE-----" not in text and "PRIVATE KEY" not in text:
        return findings

    rel = str(path.relative_to(root))
    # Private key type
    if "BEGIN RSA PRIVATE KEY" in text or "BEGIN RSA PUBLIC KEY" in text:
        findings.append(Finding(
            id=f"CERT-{path.name}-rsa",
            evidence_path=rel,
            evidence_line=1,
            evidence_snippet="RSA key material",
            family="RSA",
            quantum_status=QuantumStatus.VULNERABLE,
            role="key",
            source_scanner="qci-cert",
            confidence=0.95,
            notes="PEM contains RSA key",
        ))
    if "BEGIN EC PRIVATE KEY" in text or "BEGIN EC PUBLIC KEY" in text:
        findings.append(Finding(
            id=f"CERT-{path.name}-ec",
            evidence_path=rel,
            evidence_line=1,
            evidence_snippet="EC key material",
            family="ECDSA",
            quantum_status=QuantumStatus.VULNERABLE,
            role="key",
            source_scanner="qci-cert",
            confidence=0.95,
            notes="PEM contains EC key",
        ))

    # Crude certificate algorithm hint from base64 (look for common OIDs in decoded form is heavy;
    # instead flag presence and recommend manual review)
    if "BEGIN CERTIFICATE" in text:
        findings.append(Finding(
            id=f"CERT-{path.name}-x509",
            evidence_path=rel,
            evidence_line=1,
            evidence_snippet="X.509 certificate",
            family="X509-Cert",
            quantum_status=QuantumStatus.UNKNOWN,
            role="cert",
            source_scanner="qci-cert",
            confidence=0.9,
            notes="Certificate present — inspect public-key and signature algorithm",
            recommendation="Check signature algorithm (RSA/ECDSA vs ML-DSA) and key size",
        ))
    return findings
