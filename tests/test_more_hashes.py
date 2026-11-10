from pathlib import Path
from qci_pqc.scanner import scan_path

def test_additional_hashes():
    findings = list(scan_path(Path("tests/fixtures/hashes")))
    families = {f.family for f in findings}
    for name in ("SHA-224", "SHA-384", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256", "RIPEMD-160"):
        assert name in families, name
