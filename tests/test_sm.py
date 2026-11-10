from pathlib import Path
from qci_pqc.scanner import scan_path

def test_sm2_sm3_sm4_detected():
    findings = list(scan_path(Path("tests/fixtures/sm")))
    families = {f.family for f in findings}
    assert "SM2" in families
    assert "SM3" in families
    assert "SM4" in families
