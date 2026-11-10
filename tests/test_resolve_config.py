from pathlib import Path
from qci_pqc.resolve import resolve_configs

def test_json_config_reports_aes_cbc():
    findings = resolve_configs(Path(__file__).parent / "fixtures")
    assert any(f.family == "AES-CBC" for f in findings)
