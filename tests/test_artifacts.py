from pathlib import Path
from qci_pqc.artifacts import scan_artifacts

def test_class_constant_pool_names_the_class():
    hits = scan_artifacts(Path("tests/fixtures/artifacts"))
    rsa = [f for f in hits if f.family == "RSA"]
    assert rsa
    assert "Signer" in rsa[0].evidence_snippet
    assert rsa[0].parameter_set == "SHA-256"

def test_hmac_parameter():
    hits = scan_artifacts(Path("tests/fixtures/artifacts"))
    hmac = [f for f in hits if f.family == "HMAC"]
    assert hmac and hmac[0].parameter_set == "SHA-256"

def test_native_and_manifest():
    hits = scan_artifacts(Path("tests/fixtures/artifacts"))
    native = [f for f in hits if f.family == "OpenSSL"]
    assert native and native[0].parameter_set == "3.0.2"
    mf = [f for f in hits if "manifest" in f.evidence_snippet]
    assert mf and mf[0].parameter_set == "1.80"
