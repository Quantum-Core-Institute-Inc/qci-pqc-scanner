from pathlib import Path
from qci_pqc.scanner import scan_path
def test_csharp_rust():
    fams = {f.family for f in scan_path(Path("tests/fixtures/langs"))}
    assert "RSA" in fams and "AES" in fams
