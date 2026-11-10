"""Real X.509 certificate parsing (optional cryptography dependency)."""

from pathlib import Path

from .models import Finding, QuantumStatus

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def inspect_pem(path: Path, root: Path) -> list[Finding]:
    """Parse PEM certificates and keys. Uses cryptography if available."""
    findings = []
    try:
        data = path.read_bytes()
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    rel = str(path.relative_to(root))

    if HAS_CRYPTO and b"-----BEGIN CERTIFICATE-----" in data:
        findings.extend(_parse_certs(data, rel))
    elif "BEGIN CERTIFICATE" in text:
        findings.append(_basic_cert(rel))

    if "BEGIN RSA PRIVATE KEY" in text or "BEGIN RSA PUBLIC KEY" in text:
        findings.append(_key_finding(rel, "RSA", "PEM contains RSA key"))
    if "BEGIN EC PRIVATE KEY" in text or "BEGIN EC PUBLIC KEY" in text:
        findings.append(_key_finding(rel, "ECDSA", "PEM contains EC key"))
    if HAS_CRYPTO and ("BEGIN PRIVATE KEY" in text or "BEGIN PUBLIC KEY" in text):
        parsed = _parse_pkcs8(data, rel)
        if parsed:
            findings.append(parsed)

    return findings


def _parse_certs(data: bytes, rel: str) -> list[Finding]:
    findings = []
    try:
        for cert in x509.load_pem_x509_certificates(data):
            findings.extend(_from_cert(cert, rel))
    except Exception:
        # Fallback: try single cert
        try:
            cert = x509.load_pem_x509_certificate(data)
            findings.extend(_from_cert(cert, rel))
        except Exception:
            findings.append(_basic_cert(rel))
    return findings


def _from_cert(cert, rel: str) -> list[Finding]:
    pub = cert.public_key()
    sig_oid = cert.signature_algorithm_oid.dotted_string
    sig_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

    if isinstance(pub, rsa.RSAPublicKey):
        family = "RSA"
        status = QuantumStatus.VULNERABLE
        key_bits = pub.key_size
        note = f"RSA-{key_bits} certificate; signature {sig_name} ({sig_oid})"
        rec = "Migrate signature to ML-DSA (FIPS 204). Prefer ML-DSA-65 or higher."
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        family = "ECDSA"
        status = QuantumStatus.VULNERABLE
        curve = pub.curve.name
        note = f"ECDSA ({curve}) certificate; signature {sig_name}"
        rec = "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)."
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        family = "Ed25519"
        status = QuantumStatus.VULNERABLE
        note = f"Ed25519 certificate; signature {sig_name}"
        rec = "Ed25519 is quantum-vulnerable. Migrate to ML-DSA or SLH-DSA."
    else:
        oid = getattr(cert, "public_key_algorithm_oid", None)
        oid_s = oid.dotted_string if oid else ""
        mldsa = {
            "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
            "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
            "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
        }
        if oid_s in mldsa:
            family = mldsa[oid_s]
            status = QuantumStatus.PQC
            note = f"{family} certificate; OID {oid_s}"
            rec = "ML-DSA certificate. Confirm parameter set meets policy."
        else:
            family = "X509-Cert"
            status = QuantumStatus.UNKNOWN
            note = f"Certificate; signature {sig_name} ({sig_oid})"
            rec = "Inspect public-key algorithm and plan PQC migration."

    not_after = cert.not_valid_after_utc.date().isoformat()
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    sig = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else sig_name

    key = Finding(
        id=f"CERT-{rel}",
        evidence_path=rel,
        evidence_line=1,
        evidence_snippet=f"{family} cert exp={not_after}",
        family=family,
        quantum_status=status,
        role="cert",
        source_scanner="qci-x509",
        confidence=0.95,
        notes=f"{note}; subject={subject}; notAfter={not_after}; signature={sig}",
        recommendation=rec,
        parameter_set=(
            f"{family}-{getattr(pub, 'key_size', '')}" if getattr(pub, "key_size", None)
            else (getattr(getattr(pub, "curve", None), "name", "") or family)
        ),
        subject=subject,
        not_after=not_after,
        curve=getattr(getattr(pub, "curve", None), "name", "") or "",
        issuer=issuer,
    )
    sig_fam = sig or sig_name
    sig_status = QuantumStatus.PQC if "ML-DSA" in sig_fam or "MLDSA" in sig_fam else QuantumStatus.VULNERABLE
    signature = Finding(
        id=f"CERTSIG-{rel}",
        evidence_path=rel,
        evidence_line=1,
        evidence_snippet=f"signature {sig_fam}",
        family=sig_fam,
        quantum_status=sig_status,
        role="sign",
        source_scanner="qci-x509",
        confidence=0.9,
        notes=f"Certificate signature algorithm {sig_fam}",
        parameter_set=sig_fam,
    )
    return [key, signature]


def _basic_cert(rel: str) -> Finding:
    return Finding(
        id=f"CERT-{rel}",
        evidence_path=rel,
        evidence_line=1,
        evidence_snippet="X.509 certificate",
        family="X509-Cert",
        quantum_status=QuantumStatus.UNKNOWN,
        role="cert",
        source_scanner="qci-cert",
        confidence=0.7,
        notes="Certificate present (cryptography library not available for full parse)",
        recommendation="Install cryptography and re-scan for algorithm/key size",
    )


def _key_finding(rel: str, family: str, note: str) -> Finding:
    return Finding(
        id=f"KEY-{rel}-{family}",
        evidence_path=rel,
        evidence_line=1,
        evidence_snippet=f"{family} key material",
        family=family,
        quantum_status=QuantumStatus.VULNERABLE,
        role="key",
        source_scanner="qci-cert",
        confidence=0.95,
        notes=note,
    )


def _parse_pkcs8(data: bytes, rel: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
    key = None
    try:
        key = load_pem_private_key(data, password=None)
    except Exception:
        try:
            key = load_pem_public_key(data)
        except Exception:
            return None
    name = type(key).__name__.upper()
    if "MLDSA44" in name or "ML-DSA-44" in name:
        family, status = "ML-DSA-44", QuantumStatus.PQC
    elif "MLDSA65" in name:
        family, status = "ML-DSA-65", QuantumStatus.PQC
    elif "MLDSA87" in name:
        family, status = "ML-DSA-87", QuantumStatus.PQC
    elif "MLKEM512" in name:
        family, status = "ML-KEM-512", QuantumStatus.PQC
    elif "MLKEM768" in name:
        family, status = "ML-KEM-768", QuantumStatus.PQC
    elif "MLKEM1024" in name:
        family, status = "ML-KEM-1024", QuantumStatus.PQC
    elif "RSA" in name:
        family, status = "RSA", QuantumStatus.VULNERABLE
    elif "EC" in name or "ELLIPTIC" in name:
        family, status = "ECDSA", QuantumStatus.VULNERABLE
    else:
        family, status = "PKCS8", QuantumStatus.UNKNOWN
    return Finding(
        id=f"KEY-{rel}-{family}",
        evidence_path=rel,
        evidence_line=1,
        evidence_snippet=f"{family} PKCS#8",
        family=family,
        quantum_status=status,
        role="key",
        source_scanner="qci-x509",
        confidence=0.95,
        notes=f"Parsed PKCS#8/SPKI key type {name}",
        parameter_set=str(getattr(key, "key_size", "") or ""),
    )
