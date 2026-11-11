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
    mf = [f for f in hits if "Manifest 1.80" in (f.notes or "")]
    assert mf
    assert not any(f.family == "JAR" for f in hits)

def test_image_tarball_config():
    hits = scan_artifacts.__wrapped__ if False else None
    from qci_pqc.artifacts import scan_images
    hits = scan_images(Path("tests/fixtures/artifacts"))
    assert any("image.tar" in (f.evidence_path or "") and f.role == "config" for f in hits)
