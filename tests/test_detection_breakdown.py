from pathlib import Path
from qci_pqc.calibrate import calibrate

def test_breakdown_names_the_corpus():
    m = calibrate(Path("tests/corpus"))
    assert m["corpus"] == "bundled"
    assert m["independent"] is False
    assert "python" in m["by_surface"]
    assert m["by_surface"]["python"]["recall"] >= 0
