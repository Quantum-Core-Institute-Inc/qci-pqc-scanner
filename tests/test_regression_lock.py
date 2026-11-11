"""Lock the six errors from the v2.3.4 review."""
import json
from pathlib import Path
from qci_pqc.scanner import scan_path
from qci_pqc.models import Finding, Inventory, QuantumStatus
from qci_pqc.report import to_cyclonedx

GOLDEN = [
    ("createHash", 'crypto.createHash("sha1")', "SHA-1"),
    ("createHmac", 'crypto.createHmac("sha256", key)', "HMAC"),
    ("getInstance", 'Cipher.getInstance("AES/GCM/NoPadding")', "AES"),
]

def test_each_allowed_api_is_found(tmp_path):
    for name, code, family in GOLDEN:
        f = tmp_path / f"{name}.js"
        f.write_text(code + "\n")
    hits = list(scan_path(tmp_path))
    found = {h.family for h in hits}
    for name, code, family in GOLDEN:
        assert family in found, f"{name} was dropped"

def test_a_binary_is_not_scanned_as_source(tmp_path):
    blob = tmp_path / "app"
    blob.write_bytes(b"\x00\x01DH\x00" + b"\x00" * 64)
    hits = [h for h in scan_path(tmp_path) if h.family == "DH"]
    assert hits == []

def test_cbom_links_the_root_to_each_finding():
    inv = Inventory(project="app", findings=[
        Finding(id="Q1", evidence_path="a.py", evidence_line=1, evidence_snippet="x",
                family="RSA", quantum_status=QuantumStatus.VULNERABLE),
    ])
    cbom = to_cyclonedx(inv)
    assert cbom["dependencies"][0]["ref"] == "app"
    assert "Q1" in cbom["dependencies"][0]["dependsOn"]
    assert '"version": null' not in json.dumps(cbom)

def test_a_wrapper_is_reported_at_the_call_site(tmp_path):
    (tmp_path / "wrap.py").write_text('def encrypt():\n    return Cipher.getInstance("AES")\n')
    (tmp_path / "use.py").write_text("from wrap import encrypt\nencrypt()\n")
    hits = [h for h in scan_path(tmp_path) if h.family == "AES"]
    paths = {h.evidence_path for h in hits}
    assert any("use.py" in p for p in paths), "call site was not reported"
