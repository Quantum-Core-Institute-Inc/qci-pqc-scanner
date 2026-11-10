"""ShorList-inspired coverage scoring for the internal scanner.
Uses a small embedded set of forms to estimate recognition rate.
"""

from .models import CoverageScore, Finding, QuantumStatus

# Minimal embedded catalogue of forms the scanner is expected to recognise
# (positive forms only for simplicity in MVP)
KNOWN_FORMS = [
    ("rsa.generate_private_key", "RSA", QuantumStatus.VULNERABLE),
    ("ec.generate_private_key", "ECDSA", QuantumStatus.VULNERABLE),
    ("hashlib.md5", "MD5", QuantumStatus.WEAK),
    ("hashlib.sha1", "SHA-1", QuantumStatus.WEAK),
    ("Cipher.getInstance(\"AES/ECB", "AES-ECB", QuantumStatus.SAFE_SYMMETRIC),
    ("Signature.getInstance(\"SHA256withRSA", "RSA", QuantumStatus.VULNERABLE),
    ("rsa.GenerateKey", "RSA", QuantumStatus.VULNERABLE),
    ("-----BEGIN RSA PRIVATE KEY-----", "RSA", QuantumStatus.VULNERABLE),
    ("mlkem", "PQC", QuantumStatus.PQC),
]


def score_scanner(findings: list[Finding]) -> dict[str, CoverageScore]:
    """Estimate coverage based on whether known forms appear in findings."""
    quantum = CoverageScore(total=sum(1 for _, _, s in KNOWN_FORMS if s == QuantumStatus.VULNERABLE))
    weak = CoverageScore(total=sum(1 for _, _, s in KNOWN_FORMS if s == QuantumStatus.WEAK))
    pqc = CoverageScore(total=sum(1 for _, _, s in KNOWN_FORMS if s == QuantumStatus.PQC))

    found_families = {(f.family, f.quantum_status) for f in findings}

    for literal, family, status in KNOWN_FORMS:
        matched = any(
            family.lower() in f.family.lower() or literal.lower() in f.evidence_snippet.lower()
            for f in findings
        )
        if status == QuantumStatus.VULNERABLE:
            if matched:
                quantum.recognised += 1
        elif status == QuantumStatus.WEAK:
            if matched:
                weak.recognised += 1
        elif status == QuantumStatus.PQC:
            if matched:
                pqc.recognised += 1

    return {
        "quantum": quantum,
        "weak": weak,
        "pqc": pqc,
    }


def compute_readiness(findings: list[Finding]) -> tuple[float, list[Finding], dict]:
    """Transparent readiness score.

    Formula (documented):
      Start at 100.
      -15 per Shor-vulnerable public-key finding (RSA, ECDSA, etc.)
      -5  per classically weak finding (MD5, SHA-1, DES, …)
      +2  per PQC finding (capped so it cannot exceed 100)
      Result clamped to 0–100.

    Returns (score, priority_list, breakdown_dict).
    """
    if not findings:
        breakdown = {
            "vulnerable_count": 0,
            "weak_count": 0,
            "pqc_count": 0,
            "penalty_vulnerable": 0,
            "penalty_weak": 0,
            "bonus_pqc": 0,
            "formula": "100 - (vulnerable×15) - (weak×5) + (pqc×2)",
        }
        return 100.0, [], breakdown

    vulnerable = [f for f in findings if f.quantum_status == QuantumStatus.VULNERABLE]
    weak = [f for f in findings if f.classical_weak or f.quantum_status == QuantumStatus.WEAK]
    pqc = [f for f in findings if f.quantum_status == QuantumStatus.PQC]

    pen_v = len(vulnerable) * 15
    pen_w = len(weak) * 5
    bonus = len(pqc) * 2
    raw = 100.0 - pen_v - pen_w + bonus
    score = max(0.0, min(100.0, raw))

    breakdown = {
        "vulnerable_count": len(vulnerable),
        "weak_count": len(weak),
        "pqc_count": len(pqc),
        "penalty_vulnerable": pen_v,
        "penalty_weak": pen_w,
        "bonus_pqc": bonus,
        "raw": round(raw, 1),
        "formula": "100 - (vulnerable×15) - (weak×5) + (pqc×2)",
    }

    priority = sorted(
        vulnerable + weak,
        key=lambda f: (0 if f.quantum_status == QuantumStatus.VULNERABLE else 1, f.evidence_path),
    )
    return round(score, 1), priority[:20], breakdown
