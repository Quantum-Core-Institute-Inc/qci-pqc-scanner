from pathlib import Path
from qci_pqc.scanner import scan_path

def test_createhash_sha1_is_found(tmp_path):
    f = tmp_path / "app.js"
    f.write_text('const h = crypto.createHash("sha1");\n')
    hits = [x for x in scan_path(tmp_path) if x.family == "SHA-1"]
    assert hits, "createHash sha1 was dropped"
    assert "SHA-1" in hits[0].parameter_set.upper() or hits[0].parameter_set.upper() == "SHA1"
