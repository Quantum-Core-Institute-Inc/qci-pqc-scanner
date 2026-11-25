from qci_pqc.scanner import scan_path

def test_slh_sha2_128s(tmp_path):
    (tmp_path / "a.py").write_text('sig = oqs.Signature("SLH-DSA-SHA2-128s")\n')
    hits = [h for h in scan_path(tmp_path) if h.family == "SLH-DSA"]
    assert hits and hits[0].parameter_set == "SHA2-128s"

def test_slh_shake_256f(tmp_path):
    (tmp_path / "a.py").write_text('sig = oqs.Signature("SLH-DSA-SHAKE-256f")\n')
    hits = [h for h in scan_path(tmp_path) if h.family == "SLH-DSA"]
    assert hits and hits[0].parameter_set == "SHAKE-256f"

def test_slh_bare_has_no_set(tmp_path):
    (tmp_path / "a.py").write_text('sig = oqs.Signature("SPHINCS+")\n')
    hits = [h for h in scan_path(tmp_path) if h.family == "SLH-DSA"]
    assert hits and not hits[0].parameter_set
