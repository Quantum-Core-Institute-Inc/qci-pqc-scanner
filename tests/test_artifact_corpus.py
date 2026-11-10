import json
from pathlib import Path
from qci_pqc.artifacts import scan_artifacts

def test_published_artifact_corpus():
    root = Path("tests/corpus/artifacts")
    expected = json.loads((root / "expected.json").read_text())["positives"]
    hits = {(Path(f.evidence_path).name, f.family) for f in scan_artifacts(root)}
    for pair in expected:
        assert tuple(pair) in hits
