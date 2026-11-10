from pathlib import Path
from qci_pqc.scanner import scan_path

def test_enum_field_resolves_to_sha1():
    findings = list(scan_path(Path(__file__).parent / "fixtures"))
    sha1 = [f for f in findings if f.evidence_path.endswith("enum_cross.java") and f.family == "SHA-1"]
    assert sha1, "expected SHA-1 from HashPolicy.LEGACY.jcaName"
