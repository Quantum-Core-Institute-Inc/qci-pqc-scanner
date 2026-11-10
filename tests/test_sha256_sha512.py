from pathlib import Path
from qci_pqc.scanner import scan_path

def test_sha256_and_sha512():
    findings = list(scan_path(Path("tests/fixtures/sha")))
    families = {f.family for f in findings}
    assert "SHA-256" in families
    assert "SHA-512" in families
