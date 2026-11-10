from pathlib import Path
from qci_pqc.scanner import scan_path
def test_js_tier1():
    families = {f.family for f in scan_path(Path("tests/fixtures/js"))}
    assert {"SHA-256", "RSA", "AES"} <= families
