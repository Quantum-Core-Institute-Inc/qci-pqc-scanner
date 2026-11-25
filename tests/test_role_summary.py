from qci_pqc.models import Finding, Inventory, QuantumStatus
from qci_pqc.report import role_summary

def test_roles_differ_is_stated():
    inv = Inventory(project="app", findings=[
        Finding(id="1", evidence_path="a", evidence_line=1, evidence_snippet="x",
                family="X25519MLKEM768", quantum_status=QuantumStatus.HYBRID, role="kem"),
        Finding(id="2", evidence_path="a", evidence_line=2, evidence_snippet="y",
                family="ECDSA", quantum_status=QuantumStatus.VULNERABLE, role="sign"),
    ])
    s = role_summary(inv)
    assert "hybrid" in s
    assert "classical" in s
    assert "differ" in s

def test_same_role_is_not_flagged():
    inv = Inventory(project="app", findings=[
        Finding(id="1", evidence_path="a", evidence_line=1, evidence_snippet="x",
                family="ML-KEM", quantum_status=QuantumStatus.PQC, role="kem"),
        Finding(id="2", evidence_path="a", evidence_line=2, evidence_snippet="y",
                family="ML-DSA", quantum_status=QuantumStatus.PQC, role="sign"),
    ])
    assert "differ" not in role_summary(inv)
