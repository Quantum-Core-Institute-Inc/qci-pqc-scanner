from qci_pqc.models import Finding, QuantumStatus
from qci_pqc.scoring import compute_readiness

def _f(status):
    return Finding(id="x", evidence_path="a.py", evidence_line=1, evidence_snippet="x",
                   family="RSA" if status == QuantumStatus.VULNERABLE else "ML-KEM",
                   quantum_status=status, role="sign", source_scanner="qci", confidence=0.8)

def test_empty_is_not_scored():
    score, _, b = compute_readiness([])
    assert score is None
    assert b["scored"] is False

def test_pqc_does_not_cancel_vulnerable():
    findings = [_f(QuantumStatus.VULNERABLE)] + [_f(QuantumStatus.PQC) for _ in range(8)]
    score, _, b = compute_readiness(findings)
    assert score == 85.0
    assert b["bonus_pqc"] == 16
