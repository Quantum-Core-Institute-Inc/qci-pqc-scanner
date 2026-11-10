from pathlib import Path
from qci_pqc.crossmod import collect_constants
def test_real_shape():
    assert collect_constants(Path("tests/fixtures/crossmod"))["CIPHER"] == "AES/GCM"
