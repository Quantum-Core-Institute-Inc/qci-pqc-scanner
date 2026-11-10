from pathlib import Path
from qci_pqc.resolve import resolve_configs

def test_json_aes_includes_bits_and_mode(tmp_path):
    f = tmp_path / "cipher.json"
    f.write_text('{"storage_encryption": {"algorithm": "AES", "mode": "CBC", "key_bits": 128}}')
    findings = resolve_configs(tmp_path)
    assert any(f.family == "AES-128-CBC" for f in findings)
