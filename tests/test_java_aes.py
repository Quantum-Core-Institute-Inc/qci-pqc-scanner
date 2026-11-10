from pathlib import Path
from qci_pqc.scanner import scan_path

def test_java_aes_size_and_mode():
    findings = list(scan_path(Path("tests/fixtures/java_aes")))
    aes = [f for f in findings if f.family == "AES"]
    params = {f.parameter_set for f in aes}
    assert "128-ECB" in params
    assert "256-GCM" in params
