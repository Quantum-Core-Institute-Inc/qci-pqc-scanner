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


def test_artifact_negatives():
    import json
    expected = json.loads(Path("tests/fixtures/artifacts/expected.json").read_text())
    hits = scan_artifacts(Path("tests/fixtures/artifacts")) + scan_images(Path("tests/fixtures/artifacts"))
    for ban in expected.get("must_not", []):
        assert not any(ban.get("snippet", "") in (f.evidence_snippet or "") and (not ban.get("family") or f.family == ban["family"]) for f in hits)
