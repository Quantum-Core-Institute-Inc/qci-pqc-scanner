import json
from pathlib import Path
from qci_pqc.compliance import evidence_manifest

def test_manifest_hashes_the_final_policy_file(tmp_path):
    (tmp_path / "report.html").write_text("report")
    (tmp_path / "policy-result.json").write_text('{"passed": true}')
    m = evidence_manifest(tmp_path, {"n": 1}, policy={"passed": True}, written=["report.html", "policy-result.json"])
    assert "policy-result.json" in m["files"]
    import hashlib
    got = hashlib.sha256((tmp_path / "policy-result.json").read_bytes()).hexdigest()
    assert m["files"]["policy-result.json"]["sha256"] == got

def test_repeated_run_matches(tmp_path):
    (tmp_path / "report.html").write_text("report")
    (tmp_path / "policy-result.json").write_text('{"passed": false}')
    evidence_manifest(tmp_path, {"n": 1}, policy={"passed": False}, written=["report.html", "policy-result.json"])
    (tmp_path / "policy-result.json").write_text('{"passed": true}')
    m = evidence_manifest(tmp_path, {"n": 1}, policy={"passed": True}, written=["report.html", "policy-result.json"])
    import hashlib
    got = hashlib.sha256((tmp_path / "policy-result.json").read_bytes()).hexdigest()
    assert m["files"]["policy-result.json"]["sha256"] == got
