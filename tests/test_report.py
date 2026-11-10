import pytest

from qci_pqc.models import Finding, Inventory, QuantumStatus
from qci_pqc.report import to_cyclonedx


@pytest.mark.parametrize("mode", ["ECB", "GCM", "CBC"])
def test_cipher_mode_uses_cyclonedx_enum_case(mode):
    finding = Finding(
        id="cipher",
        evidence_path="cipher.py",
        evidence_line=1,
        evidence_snippet="AES",
        family=f"AES-256-{mode}",
        role="encrypt",
        parameter_set="256",
        quantum_status=QuantumStatus.SAFE_SYMMETRIC,
    )

    cbom = to_cyclonedx(Inventory(project="test", findings=[finding]))

    assert (
        cbom["components"][0]["cryptoProperties"]["algorithmProperties"]["mode"]
        == mode.lower()
    )


def test_protocol_finding_uses_valid_cyclonedx_primitive():
    finding = Finding(
        id="tls-protocol",
        evidence_path="nginx.conf",
        evidence_line=1,
        evidence_snippet="ssl_protocols TLSv1.0;",
        family="TLS1.0/1.1",
        role="protocol",
        quantum_status=QuantumStatus.WEAK,
    )

    cbom = to_cyclonedx(Inventory(project="test", findings=[finding]))

    assert (
        cbom["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"]
        == "other"
    )


def test_cipher_mode_uses_cyclonedx_enum_value():
    finding = Finding(
        id="aes-gcm",
        evidence_path="cipher.py",
        evidence_line=1,
        evidence_snippet="AES-256-GCM",
        family="AES-256-GCM",
        role="encrypt",
        quantum_status=QuantumStatus.SAFE_SYMMETRIC,
    )

    cbom = to_cyclonedx(Inventory(project="test", findings=[finding]))

    assert (
        cbom["components"][0]["cryptoProperties"]["algorithmProperties"]["mode"]
        == "gcm"
    )


def test_hmac_hash_uses_parameter_set_identifier():
    finding = Finding(
        id="hmac-sha256",
        evidence_path="hash.py",
        evidence_line=1,
        evidence_snippet="hmac.new(key, data, hashlib.sha256)",
        family="HMAC",
        role="mac",
        parameter_set="SHA-256",
        quantum_status=QuantumStatus.SAFE_SYMMETRIC,
    )

    algorithm = to_cyclonedx(
        Inventory(project="test", findings=[finding])
    )["components"][0]["cryptoProperties"]["algorithmProperties"]

    assert algorithm["parameterSetIdentifier"] == "SHA-256"
    assert "hash" not in algorithm
