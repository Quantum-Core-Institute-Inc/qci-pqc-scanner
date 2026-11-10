"""Actionable enrichment: prioritization, compliance, timelines, recommendations."""

from .models import Finding, QuantumStatus

# Heuristic keywords for prioritization
ROOT_CA_HINTS = ("root", "ca", "certificate authority", "firmware", "codesign", "code-sign")
EXTERNAL_HINTS = ("tls", "https", "ssh", "public", "api", "gateway", "external")
LONG_LIVED_HINTS = ("archive", "backup", "long-term", "persist", "store", "database")


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Add prioritization, compliance, timeline, and recommendation fields."""
    for f in findings:
        f.priority_score, f.priority_reasons = _priority(f)
        f.compliance_note = _compliance(f)
        f.timeline_flags = _timeline(f)
        f.recommendation = _recommendation(f)
        f.migration_phase = _phase(f)
        # Extract parameter set if present in family or snippet
        f.parameter_set = f.parameter_set or _extract_param(f)
    return findings


def _priority(f: Finding) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    path = (f.evidence_path + " " + f.evidence_snippet).lower()

    if f.quantum_status == QuantumStatus.VULNERABLE:
        score += 50
        reasons.append("Shor-vulnerable public-key")
    if f.classical_weak or f.quantum_status == QuantumStatus.WEAK:
        score += 20
        reasons.append("Classically weak")

    if any(h in path for h in ROOT_CA_HINTS):
        score += 30
        reasons.append("Possible root CA / code-signing / firmware context")
    if any(h in path for h in EXTERNAL_HINTS):
        score += 15
        reasons.append("Possible external-facing interface")
    if any(h in path for h in LONG_LIVED_HINTS):
        score += 10
        reasons.append("Possible long-lived data context")

    if f.quantum_status == QuantumStatus.PQC:
        score -= 10  # positive signal
    return score, reasons


def _compliance(f: Finding) -> str:
    fam = f.family.lower()
    snippet = f.evidence_snippet.lower()
    notes = []

    # Pre-standard detection
    if any(x in snippet or x in fam for x in ("kyber", "crystals-kyber")):
        notes.append("Pre-standard Kyber — prefer ML-KEM (FIPS 203)")
    if any(x in snippet or x in fam for x in ("dilithium", "crystals-dilithium")):
        notes.append("Pre-standard Dilithium — prefer ML-DSA (FIPS 204)")

    # Parameter-set validation against common recommendations
    param = (f.parameter_set or "").lower()
    if "ml-kem" in fam or "mlkem" in fam:
        if "512" in param or "512" in fam:
            notes.append("ML-KEM-512 is smaller; ML-KEM-768 is the usual default")
        elif "1024" in param or "1024" in fam:
            notes.append("ML-KEM-1024 is high-assurance")
        else:
            notes.append("ML-KEM (FIPS 203) — recommend ML-KEM-768 unless size-constrained")
    if "ml-dsa" in fam or "mldsa" in fam:
        if "44" in param or "44" in fam:
            notes.append("ML-DSA-44 is size-optimized; consider ML-DSA-65 for general use")
        elif "87" in param or "87" in fam:
            notes.append("ML-DSA-87 meets CNSA 2.0 for U.S. national security systems")
        else:
            notes.append("ML-DSA (FIPS 204) — ML-DSA-65 is the common default")

    if "slh-dsa" in fam or "sphincs" in fam:
        notes.append("SLH-DSA (FIPS 205) — hash-based, larger signatures")

    return "; ".join(notes) if notes else ""


def _timeline(f: Finding) -> list[str]:
    flags = []
    if f.quantum_status != QuantumStatus.VULNERABLE:
        return flags

    flags.append("Deprecated after 2030 (IR 8547)")
    flags.append("Disallowed after 2035 (IR 8547)")

    role = (f.role or "").lower()
    fam = f.family.lower()
    # Role-aware
    is_kem = role in ("kem", "kex", "keygen", "key") or any(x in fam for x in ("kem", "dh", "ecdh", "rsa")) and "sign" not in role
    is_sign = role in ("sign", "signature", "hostkey") or any(x in fam for x in ("dsa", "ecdsa", "eddsa", "rsa")) and role != "kem"

    if is_kem or (not is_sign and "key" in role):
        flags.append("Federal high-value key establishment: 31 Dec 2030")
    if is_sign or "sign" in role or "dsa" in fam or "ecdsa" in fam:
        flags.append("Federal high-value signatures: 31 Dec 2031")
    return flags


def _recommendation(f: Finding) -> str:
    fam = f.family.lower()
    role = (f.role or "").lower()

    if f.quantum_status == QuantumStatus.VULNERABLE:
        if role in ("kem", "kex", "keygen") or "kem" in fam or "dh" in fam:
            return "Migrate key establishment to ML-KEM-768 (FIPS 203). Use hybrid (e.g. X25519+ML-KEM) during transition."
        if role in ("sign", "signature") or "dsa" in fam or "ecdsa" in fam or "rsa" in fam:
            return "Migrate signatures to ML-DSA-65 (FIPS 204). Use SLH-DSA (FIPS 205) for root/firmware. Consider hybrid."
        return "Replace with NIST PQC (ML-KEM or ML-DSA/SLH-DSA) or a validated hybrid."

    if f.quantum_status == QuantumStatus.HYBRID:
        # Basic hybrid validation note
        snippet = f.evidence_snippet.lower()
        has_classical = any(x in snippet for x in ("x25519", "secp", "ecdsa", "rsa", "ed25519"))
        has_pqc = any(x in snippet for x in ("mlkem", "ml-kem", "mldsa", "ml-dsa", "kyber", "dilithium"))
        if has_classical and has_pqc:
            return "Hybrid appears to contain both classical and PQC components — good transition pattern. Plan pure-PQC cutover."
        return "Hybrid detected; verify both classical and PQC components are present and correctly paired."

    if "ml-dsa" in fam:
        if "44" in fam:
            return "Consider ML-DSA-65 for general-purpose use unless size is critical."
        if "87" in fam:
            return "ML-DSA-87 is appropriate for high-assurance and CNSA 2.0."
        return "ML-DSA-65 is the recommended general-purpose parameter set."
    if "ml-kem" in fam:
        return "ML-KEM-768 is the recommended default for most key-establishment uses."
    return ""


def _phase(f: Finding) -> str:
    if f.quantum_status == QuantumStatus.VULNERABLE:
        return "Phase 2–3 (Prioritize & Select) → Phase 5–6 (Implement & Deploy)"
    if f.quantum_status == QuantumStatus.HYBRID:
        return "Phase 5–6 (Transition) → Phase 7 (Retire classical)"
    if f.quantum_status == QuantumStatus.PQC:
        return "Phase 3–5 (Already using PQC) — verify FIPS compliance & parameter set"
    return "Review"


def _extract_param(f: Finding) -> str | None:
    text = (f.family + " " + f.evidence_snippet).lower()
    for p in ("ml-kem-512", "ml-kem-768", "ml-kem-1024", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
              "kyber512", "kyber768", "kyber1024", "dilithium2", "dilithium3", "dilithium5"):
        if p in text.replace("-", "").replace("_", "") or p in text:
            return p.upper().replace("KYBER", "ML-KEM-").replace("DILITHIUM", "ML-DSA-")
    return None
