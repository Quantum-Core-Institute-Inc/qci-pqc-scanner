from qci_pqc.scanner import scan_path

def test_sshd_rsa(tmp_path):
    (tmp_path / "sshd_config").write_text("HostKeyAlgorithms ssh-rsa\n")
    assert any(h.family == "RSA" for h in scan_path(tmp_path))

def test_openssl_sha1(tmp_path):
    (tmp_path / "openssl.cnf").write_text("default_md = sha1\n")
    assert any(h.family == "SHA-1" for h in scan_path(tmp_path))

def test_ike_3des(tmp_path):
    (tmp_path / "ipsec.conf").write_text("ike=3des-sha1-modp1024!\n")
    assert any(h.family == "3DES" for h in scan_path(tmp_path))
