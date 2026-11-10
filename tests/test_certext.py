from qci_pqc.certext import chain_length, extension_names
from pathlib import Path

def test_chain(tmp_path: Path):
    p = tmp_path / "c.pem"
    p.write_text("-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n")
    assert chain_length(p) == 2

def test_ext():
    assert "Key Usage" in extension_names("X509v3 Key Usage: Digital Signature")
