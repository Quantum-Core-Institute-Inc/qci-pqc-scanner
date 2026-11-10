"""Accuracy calibration test."""
import json
from pathlib import Path
import subprocess
import sys

from qci_pqc.calibrate import calibrate

def test_calibration_metrics():
    corpus = Path(__file__).parent / "corpus"
    result = calibrate(corpus)
    assert result["precision"] >= 0.5
    assert result["recall"] >= 0.5
    assert result["true_positives"] > 0
    assert "false_positives" in result


def test_calibration_json_stdout_is_parseable():
    corpus = Path(__file__).parent / "corpus"
    result = subprocess.run(
        [sys.executable, "-m", "qci_pqc.cli", "scan", str(corpus), "--calibrate", "--json"],
        capture_output=True,
        text=True,
        check=True,
    )

    metrics = json.loads(result.stdout)
    assert metrics["recall"] >= 0.9
    assert "Scanning" in result.stderr
