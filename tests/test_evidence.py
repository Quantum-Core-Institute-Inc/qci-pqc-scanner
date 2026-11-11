from qci_pqc.compliance import evidence_manifest
from pathlib import Path

def test_manifest_names_build_and_policy(tmp_path):
    (tmp_path / "report.html").write_text("x")
    m = evidence_manifest(tmp_path, {"n": 1}, policy={"passed": True}, revision="abc123")
    assert m["scanner_build"]
    assert m["input_revision"] == "abc123"
    assert m["policy"]["passed"] is True
