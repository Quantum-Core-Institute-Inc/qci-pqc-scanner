from pathlib import Path
from qci_pqc.artifacts import scan_artifacts

def test_class_constant_pool_names_the_class():
    hits = scan_artifacts(Path("tests/fixtures/artifacts"))
    rsa = [f for f in hits if f.family == "RSA"]
    assert rsa
    assert "Signer.sign" in rsa[0].evidence_snippet
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

def test_ssl_substring_is_not_openssl():
    from qci_pqc.artifacts import _native
    assert _native("lib/libsslfoo.so").family == "Native"
    assert _native("lib/libssl.so").family == "OpenSSL"
    assert _native("lib/bcprov-jdk18on-1.80.so").family == "BouncyCastle"

def test_loose_native():
    hits = scan_artifacts(Path("tests/fixtures/artifacts"))
    ssl = [f for f in hits if f.evidence_snippet == "libssl.so"]
    assert ssl and ssl[0].family == "OpenSSL"
    foo = [f for f in hits if f.evidence_snippet == "libsslfoo.so"]
    assert foo and foo[0].family == "Native"

def test_jar_inside_war():
    hits = scan_artifacts(Path("tests/fixtures/artifacts"))
    assert any("app.war" in (f.evidence_snippet or "") and f.family == "RSA" for f in hits)

def test_wheel():
    hits = scan_artifacts(Path("tests/fixtures/artifacts"))
    assert any("cryptography.whl" in (f.evidence_path or "") and f.family == "OpenSSL" for f in hits)
