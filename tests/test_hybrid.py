"""Hybrid key-exchange detection."""
from pathlib import Path

from qci_pqc.report import to_cyclonedx
from qci_pqc.scanner import scan_path
from qci_pqc.models import Inventory

CORPUS = Path(__file__).parent / "corpus"


def test_hybrid_groups_are_named():
    findings = list(scan_path(CORPUS))
    hybrid = [f for f in findings if f.evidence_path.endswith("hybrid_kex.conf")]
    families = {f.family for f in hybrid}
    assert "X25519MLKEM768" in families
    assert "SecP384r1MLKEM1024" in families
    assert "sntrup761x25519" in families
    assert "TLS-1.3" in families
    named = [f for f in hybrid if f.family == "X25519MLKEM768"]
    assert named and all(f.parameter_set == "X25519MLKEM768" for f in named)


def test_hybrid_cbom_has_parameter_and_protocol():
    findings = [f for f in scan_path(CORPUS) if f.evidence_path.endswith("hybrid_kex.conf")]
    bom = to_cyclonedx(Inventory(project="hybrid", findings=findings))
    by_name = {c["name"]: c for c in bom["components"]}
    assert by_name["X25519MLKEM768"]["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] == "X25519MLKEM768"
    proto = by_name["TLS-1.3"]["cryptoProperties"]["protocolProperties"]
    assert proto["type"] == "tls"
    assert proto["version"] == "TLSv1.3"
