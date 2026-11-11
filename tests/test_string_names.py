from pathlib import Path
from qci_pqc.scanner import scan_path

def test_names_in_strings_are_not_uses():
    hits = list(scan_path(Path("tests/fixtures/strings")))
    assert hits == []
