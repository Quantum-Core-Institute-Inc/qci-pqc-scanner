from qci_pqc.baseline import diff, key
from qci_pqc.models import Finding, QuantumStatus

def _f(fam, name):
    return Finding(id="1", evidence_path=name, evidence_line=1, evidence_snippet="", family=fam, role="key", quantum_status=QuantumStatus.VULNERABLE)

def test_baseline_diff():
    old = {key(_f("RSA", "a.py"))}
    result = diff([_f("RSA", "a.py"), _f("AES", "b.py")], old)
    assert "AES|b.py|None" in result["new"]
    assert result["resolved"] == []
