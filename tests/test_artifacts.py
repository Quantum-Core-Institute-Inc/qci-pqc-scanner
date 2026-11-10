from pathlib import Path
from qci_pqc.artifacts import scan_artifacts

def test_class_string(tmp_path: Path):
    (tmp_path / "A.class").write_bytes(b"\xca\xfe\xba\xbeAES/GCM/NoPadding")
    hits = scan_artifacts(tmp_path)
    assert any(f.family == "AES" and f.source_scanner == "qci-artifact" for f in hits)
