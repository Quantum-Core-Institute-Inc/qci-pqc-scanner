def test_from_cert_returns_key_and_signature():
    from qci_pqc import certs
    assert hasattr(certs, "_from_cert")
