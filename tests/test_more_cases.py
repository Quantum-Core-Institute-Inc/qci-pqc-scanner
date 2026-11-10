from pathlib import Path
from qci_pqc.scanner import scan_path

def test_env_default_and_concat_and_enum():
    findings = list(scan_path(Path(__file__).parent / "fixtures"))
    fams = {f.family for f in findings}
    assert "SHA-1" in fams
    assert "3DES" in fams
