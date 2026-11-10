from qci_pqc.baseline import diff, key
from qci_pqc.models import Finding, QuantumStatus

def test_artifact_is_not_a_regression():
    old = {key(Finding(id="1", evidence_path="a.py", evidence_line=1, evidence_snippet="", family="RSA", role="key", quantum_status=QuantumStatus.VULNERABLE))}
    art = Finding(id="2", evidence_path="a.jar", evidence_line=0, evidence_snippet="", family="AES", role="cipher", quantum_status=QuantumStatus.SAFE_SYMMETRIC, source_scanner="qci-artifact")
    result = diff([art], old)
    assert result["new"] == []
