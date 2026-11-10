from pathlib import Path
from qci_pqc.scanner import scan_path
def test_tls13_suites():
    families = {f.family for f in scan_path(Path("tests/fixtures/tls13"))}
    assert {"AES", "ChaCha20-Poly1305"} <= families
