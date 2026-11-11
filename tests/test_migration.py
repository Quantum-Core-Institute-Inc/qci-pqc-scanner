from pathlib import Path
from qci_pqc.models import Finding, QuantumStatus
from qci_pqc.compliance import export_tickets

def test_ticket_has_an_owner(tmp_path):
    f = Finding(id="x", evidence_path="pay/crypto.py", evidence_line=4, evidence_snippet="rsa",
                family="RSA", quantum_status=QuantumStatus.VULNERABLE, role="sign",
                source_scanner="qci", confidence=0.8)
    f.owner = "payments"
    f.lifetime = "10y"
    n = export_tickets([f], tmp_path / "tickets.json")
    assert n == 1
    import json
    ticket = json.loads((tmp_path / "tickets.json").read_text())[0]
    assert ticket["owner"] == "payments"
    assert ticket["data_lifetime"] == "10y"
