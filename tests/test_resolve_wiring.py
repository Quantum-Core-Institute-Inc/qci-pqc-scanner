from pathlib import Path
from qci_pqc.resolve import resolve_wiring

def test_factory_reports_aes(tmp_path):
    f = tmp_path / "Factory.java"
    f.write_text('return new AesCbcCipher(256);')
    findings = resolve_wiring(tmp_path)
    assert any(f.family == "AES-CBC" for f in findings)
