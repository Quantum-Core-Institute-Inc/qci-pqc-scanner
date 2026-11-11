from pathlib import Path
from qci_pqc.artifacts import scan_artifacts

def test_class_constant_pool_names_the_class():
    hits = scan_artifacts(Path("tests/fixtures/artifacts"))
    rsa = [f for f in hits if f.family == "RSA"]
    assert rsa
    assert "Signer" in rsa[0].evidence_snippet
    assert "SHA256withRSA" in rsa[0].evidence_snippet
