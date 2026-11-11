from qci_pqc.models import Finding, QuantumStatus
from qci_pqc.report import to_cyclonedx

def test_sha512_is_not_pqc():
    f = Finding(id="x", evidence_path="a.py", evidence_line=1, evidence_snippet="sha512",
                family="SHA-512", quantum_status=QuantumStatus.SAFE_SYMMETRIC, role="hash",
                source_scanner="qci", confidence=0.8)
    cbom = to_cyclonedx(type("I", (), {"project": "t", "findings": [f], "readiness_score": None})())
    props = cbom["components"][0].get("cryptoProperties", {}).get("algorithmProperties", {})
    assert "nistQuantumSecurityLevel" not in props

def test_mlkem512_keeps_level():
    f = Finding(id="x", evidence_path="a.py", evidence_line=1, evidence_snippet="ML-KEM-512",
                family="ML-KEM-512", quantum_status=QuantumStatus.PQC, role="kem",
                source_scanner="qci", confidence=0.8)
    cbom = to_cyclonedx(type("I", (), {"project": "t", "findings": [f], "readiness_score": None})())
    props = cbom["components"][0].get("cryptoProperties", {}).get("algorithmProperties", {})
    assert props.get("nistQuantumSecurityLevel") == 1
