from qci_pqc.models import Finding, Inventory, QuantumStatus
from qci_pqc.report import to_cyclonedx
import json

def test_library_without_version_omits_the_field():
    f = Finding(id="DEP-x", evidence_path="req.txt", evidence_line=1, evidence_snippet="x",
                family="requests", quantum_status=QuantumStatus.VULNERABLE, role="library",
                source_scanner="qci-deps", notes="pkg:pypi/requests")
    cbom = to_cyclonedx(Inventory(project="app", findings=[f]))
    lib = cbom["components"][0]
    assert "version" not in lib
    assert lib["purl"] == "pkg:pypi/requests"
    assert json.dumps(cbom).find('"version": null') == -1
