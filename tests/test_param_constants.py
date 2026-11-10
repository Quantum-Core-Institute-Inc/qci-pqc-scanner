from pathlib import Path
from qci_pqc.scanner import scan_path

def test_key_bits_constant(tmp_path):
    f = tmp_path / "k.py"
    f.write_text("KEY_BITS = 2048\\nrsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)\\n")
    findings = list(scan_path(tmp_path))
    rsa = [x for x in findings if x.family == "RSA"]
    assert rsa and rsa[0].parameter_set == "2048"

def test_curve_constant(tmp_path):
    f = tmp_path / "c.py"
    f.write_text('CURVE = "secp384r1"\\nec.generate_private_key(ec.SECP384R1())\\n')
    findings = list(scan_path(tmp_path))
    ec = [x for x in findings if x.family == "ECDSA"]
    assert ec and ec[0].parameter_set == "P-384"
