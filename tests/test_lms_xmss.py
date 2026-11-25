from qci_pqc.scanner import scan_path

def test_java_lms(tmp_path):
    (tmp_path / "a.java").write_text('KeyPairGenerator.getInstance("LMS", "BCPQC");\n')
    hits = [h for h in scan_path(tmp_path) if h.family == "LMS"]
    assert hits

def test_java_xmss(tmp_path):
    (tmp_path / "a.java").write_text('KeyPairGenerator.getInstance("XMSS", "BCPQC");\n')
    hits = [h for h in scan_path(tmp_path) if h.family == "XMSS"]
    assert hits

def test_yaml_lms(tmp_path):
    (tmp_path / "policy.yaml").write_text("algorithm: LMS_SHA256_M32_H10\n")
    hits = [h for h in scan_path(tmp_path) if h.family == "LMS"]
    assert hits

def test_python_lms(tmp_path):
    (tmp_path / "a.py").write_text("LMS_SHA256_M32_H5 = 5\ndef lms_verify():\n    pass\n")
    hits = [h for h in scan_path(tmp_path) if h.family == "LMS"]
    assert hits
