from qci_pqc.scoresplit import split_scores
from qci_pqc.models import Finding, QuantumStatus

def test_not_blended():
    s = Finding(id="1", evidence_path="a.py", evidence_line=1, evidence_snippet="", family="RSA", role="key", quantum_status=QuantumStatus.VULNERABLE, source_scanner="qci-pattern")
    a = Finding(id="2", evidence_path="a.jar", evidence_line=0, evidence_snippet="", family="AES", role="cipher", quantum_status=QuantumStatus.SAFE_SYMMETRIC, source_scanner="qci-artifact")
    out = split_scores([s, a])
    assert out["source"]["count"] == 1
    assert out["artifact"]["count"] == 1
    assert out["blended"] is False
