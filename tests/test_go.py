from pathlib import Path
from qci_pqc.scanner import scan_path
def test_go_tier1():
    families = {f.family for f in scan_path(Path("tests/fixtures/go"))}
    assert {"RSA", "SHA-256", "AES"} <= families
