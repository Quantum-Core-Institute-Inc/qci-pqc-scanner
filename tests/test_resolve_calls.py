from pathlib import Path
from qci_pqc.resolve import resolve_calls_and_maps

def test_sysprop_default_is_reported(tmp_path):
    f = tmp_path / "T.java"
    f.write_text('Cipher.getInstance(System.getProperty("app.cipher", "AES/ECB/PKCS5Padding"));')
    findings = resolve_calls_and_maps(tmp_path)
    assert any("AES" in f.family for f in findings)
