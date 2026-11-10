"""File-local constant propagation."""
from pathlib import Path
from qci_pqc.scanner import scan_path

def test_hash_constant_is_resolved():
    findings = list(scan_path(Path(__file__).parent / "fixtures"))
    sha1 = [f for f in findings if f.evidence_path.endswith("const_prop.py") and f.family == "SHA-1"]
    assert sha1, "expected SHA-1 from HASH_ALG = 'sha1'"

def test_key_alg_constant_is_resolved():
    findings = list(scan_path(Path(__file__).parent / "fixtures"))
    dsa = [f for f in findings if f.evidence_path.endswith("const_prop.py") and f.family == "DSA"]
    assert dsa, "expected DSA from KEY_ALG = 'DSA'"
