from pathlib import Path
from click.testing import CliRunner
from qci_pqc.cli import scan

def test_policy_violation_exits_1(tmp_path):
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.py").write_text('from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
    pol = tmp_path / "policy.json"
    pol.write_text('{"fail_on": ["vulnerable"]}')
    result = CliRunner().invoke(scan, [str(target), "--policy", str(pol), "--out", str(tmp_path / "out")])
    assert result.exit_code == 1

def test_waived_finding_does_not_fail(tmp_path):
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.py").write_text('from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
    pol = tmp_path / "policy.json"
    pol.write_text('{"fail_on": ["vulnerable"]}')
    acc = tmp_path / "accepted.json"
    acc.write_text('{"accepted": [{"key": "RSA|a.py|2048", "owner": "sec", "justification": "legacy", "expires": "2030-01-01"}]}')
    result = CliRunner().invoke(scan, [str(target), "--policy", str(pol), "--accepted-risks", str(acc), "--fail-on", "vulnerable", "--out", str(tmp_path / "out")])
    assert result.exit_code == 0
