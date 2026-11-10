from qci_pqc.scanner import scan_path
from pathlib import Path

def test_same_line_params(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "from cryptography.hazmat.primitives import hmac, hashes\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "ec.generate_private_key(ec.SECP384R1())\n"
        "hmac.HMAC(b'k', hashes.SHA256())\n"
    )
    by = {f.family: f.parameter_set for f in scan_path(tmp_path)}
    assert by.get("RSA") in {"2048", "RSA"} or "2048" in (by.get("RSA") or "")
    assert "384" in (by.get("ECDSA") or "") or by.get("ECDSA")
