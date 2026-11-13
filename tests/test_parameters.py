from qci_pqc.scanner import scan_path

def test_aes_mode_from_transformation(tmp_path):
    (tmp_path / "a.java").write_text('Cipher.getInstance("AES/CBC/PKCS5Padding");\n')
    hits = [h for h in scan_path(tmp_path) if h.family == "AES"]
    assert hits
    assert "CBC" in (hits[0].parameter_set or "")

def test_rsa_size_from_the_call(tmp_path):
    (tmp_path / "a.py").write_text("key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    hits = [h for h in scan_path(tmp_path) if h.family == "RSA"]
    assert hits
    assert "2048" in (hits[0].parameter_set or "")
