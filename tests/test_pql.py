from click.testing import CliRunner
from qci_pqc.pql import pql

def test_pql_help():
    result = CliRunner().invoke(pql, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "diff" in result.output
    assert "gate" in result.output
