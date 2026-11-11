import json
from pathlib import Path
from qci_pqc.artifacts import scan_artifacts, scan_images

def test_published_artifact_corpus():
    expected = json.loads(Path("tests/fixtures/artifacts/expected.json").read_text())["expected"]
    hits = scan_artifacts(Path("tests/fixtures/artifacts")) + scan_images(Path("tests/fixtures/artifacts"))
    found = 0
    for e in expected:
        if any(e["family"] == f.family and e["snippet"] in (f.evidence_snippet or "") and (e["parameter"] or "") == (f.parameter_set or "") for f in hits):
            found += 1
    assert found == len(expected)
