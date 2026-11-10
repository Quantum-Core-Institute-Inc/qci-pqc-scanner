from qci_pqc.models import Finding, Inventory, QuantumStatus
from qci_pqc.report import to_cyclonedx


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
