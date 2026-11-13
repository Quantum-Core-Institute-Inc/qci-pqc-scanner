from qci_pqc.scanner import scan_path

def test_nginx_conf_is_read(tmp_path):
    (tmp_path / "nginx.conf").write_text("ssl_ciphers AES128-GCM-SHA256;\n")
    hits = [h for h in scan_path(tmp_path) if h.family == "AES"]
    assert hits, "nginx.conf was not read"

def test_yaml_config_is_read(tmp_path):
    (tmp_path / "app.yaml").write_text("cipher: AES-256-GCM\n")
    hits = [h for h in scan_path(tmp_path) if h.family == "AES"]
    assert hits, "yaml was not read"
    assert "256" in (hits[0].parameter_set or "") or "GCM" in (hits[0].parameter_set or "")

def test_sshd_config_is_read(tmp_path):
    (tmp_path / "sshd_config").write_text("HostKeyAlgorithms ssh-rsa\n")
    hits = [h for h in scan_path(tmp_path) if h.family == "RSA"]
    assert hits, "sshd_config was not read"
