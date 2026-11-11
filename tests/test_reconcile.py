import json
from pathlib import Path
from qci_pqc.models import Finding, QuantumStatus
from qci_pqc.reconcile import reconcile

def test_reconcile_names_the_gap(tmp_path):
    supplier = tmp_path / "supplier.json"
    supplier.write_text(json.dumps({"components": [{"name": "RSA"}, {"name": "ML-KEM"}]}))
    findings = [Finding(id="x", evidence_path="a.py", evidence_line=1, evidence_snippet="rsa",
                        family="RSA", quantum_status=QuantumStatus.VULNERABLE, role="sign",
                        source_scanner="qci", confidence=0.8)]
    result = reconcile(findings, supplier)
    assert result["in_both"] == ["RSA"]
    assert result["only_in_supplier"] == ["ML-KEM"]
    assert "RSA" not in result["only_in_scan"]
