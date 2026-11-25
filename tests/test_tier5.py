import pytest
from pathlib import Path
from qci_pqc.scanner import scan_path
@pytest.mark.skip(reason='Tier 5: names assembled at runtime are out of scope')
def test_tier5_static():
    families = {f.family for f in scan_path(Path("tests/fixtures/tier5"))}
    assert {"MD5", "SHA-1", "AES"} <= families
