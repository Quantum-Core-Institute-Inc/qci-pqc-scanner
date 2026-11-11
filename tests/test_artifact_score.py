from pathlib import Path
from qci_pqc.artifacts import scan_artifacts, scan_images
from qci_pqc.scoresplit import split_scores

def test_artifact_score_is_separate():
    hits = scan_artifacts(Path("tests/fixtures/artifacts")) + scan_images(Path("tests/fixtures/artifacts"))
    parts = split_scores(hits)
    assert parts["blended"] is False
    assert parts["artifact"]["count"] == len(hits)
    assert parts["source"]["count"] == 0
    assert parts["artifact"]["with_parameter"] >= 1
