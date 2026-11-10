from pathlib import Path
from qci_pqc.scanner import scan_path
def test_c_tier1():
    families = {f.family for f in scan_path(Path("tests/fixtures/c"))}
    assert {"MD5", "SHA-256", "AES", "RSA"} <= families
