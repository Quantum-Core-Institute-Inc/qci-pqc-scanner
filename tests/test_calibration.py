"""Accuracy calibration test."""
from pathlib import Path
from qci_pqc.calibrate import calibrate

def test_calibration_metrics():
    corpus = Path(__file__).parent / "corpus"
    result = calibrate(corpus)
    assert result["precision"] >= 0.5
    assert result["recall"] >= 0.5
    assert result["true_positives"] > 0
    assert "false_positives" in result
