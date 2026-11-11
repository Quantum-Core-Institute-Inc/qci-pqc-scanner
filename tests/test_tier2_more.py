import pytest
from pathlib import Path
from qci_pqc.scanner import scan_path
@pytest.mark.xfail(reason='known gap, v2.3 review')
def test_enum_sha1():
    families = {f.family for f in scan_path(Path("tests/fixtures/tier2"))}
    assert "SHA-1" in families
