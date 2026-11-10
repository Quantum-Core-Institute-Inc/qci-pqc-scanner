import json
from pathlib import Path
from qci_pqc.org import merge_cboms, org_score

def test_merge(tmp_path: Path):
    a = tmp_path / "a" / "cbom.json"
    b = tmp_path / "b" / "cbom.json"
    a.parent.mkdir(); b.parent.mkdir()
    a.write_text(json.dumps({"components": [{"name": "RSA"}]}))
    b.write_text(json.dumps({"components": [{"name": "AES"}]}))
    bom = merge_cboms([a, b])
    assert org_score(bom)["components"] == 2
