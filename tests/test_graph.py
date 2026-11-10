from pathlib import Path
from qci_pqc.graph import link
from qci_pqc.models import Finding, QuantumStatus

def test_link():
    f = Finding(id="1", evidence_path="requirements.txt", evidence_line=1, evidence_snippet="cryptography==48", family="Python-cryptography", role="dependency", quantum_status=QuantumStatus.VULNERABLE, source_scanner="qci-deps", parameter_set="48")
    edges = link([f], Path("/apps/pay"))
    assert edges[0]["app"] == "pay"
    assert edges[0]["library"] == "Python-cryptography"
