from pathlib import Path
from qci_pqc.scanner import scan_path
def test_envoy_pg():
    fams = {f.family for f in scan_path(Path("tests/fixtures/edge"))}
    assert "TLS-1.0" in fams
