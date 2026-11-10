from qci_pqc.scanner import _expand_constants
from pathlib import Path
import tempfile, textwrap
from qci_pqc.scanner import scan_path

def test_rsa_key_size_becomes_parameter(tmp_path):
    f = tmp_path / "k.py"
    f.write_text("rsa.generate_private_key(public_exponent=65537, key_size=2048)\\n")
    findings = list(scan_path(tmp_path))
    rsa = [x for x in findings if x.family == "RSA"]
    assert rsa and rsa[0].parameter_set == "2048"
