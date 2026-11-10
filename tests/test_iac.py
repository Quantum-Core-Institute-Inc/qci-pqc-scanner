from pathlib import Path
from qci_pqc.scanner import scan_path
def test_tf_cfn():
    fams = {f.family for f in scan_path(Path("tests/fixtures/iac"))}
    assert "RSA" in fams or "X509-Cert" in fams
