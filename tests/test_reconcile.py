import json
from pathlib import Path
from click.testing import CliRunner
from qci_pqc.cli import cli
from qci_pqc.models import Finding, QuantumStatus
from qci_pqc.reconcile import reconcile


def test_reconcile_names_the_gap(tmp_path):
    supplier = tmp_path / "supplier.json"
    supplier.write_text(json.dumps({"components": [{"name": "RSA"}, {"name": "ML-KEM"}]}))
    findings = [Finding(id="x", evidence_path="a.py", evidence_line=1, evidence_snippet="rsa",
                        family="RSA", quantum_status=QuantumStatus.VULNERABLE, role="sign",
                        source_scanner="qci", confidence=0.8)]
    result = reconcile(findings, supplier)
    assert result["in_both"] == ["RSA"]
    assert result["only_in_supplier"] == ["ML-KEM"]
    assert "RSA" not in result["only_in_scan"]


def test_scan_writes_supplier_reconciliation(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    supplier = tmp_path / "supplier.json"
    supplier.write_text(json.dumps({"components": [{"name": "ML-KEM"}]}))
    out = tmp_path / "out"

    result = CliRunner().invoke(
        cli,
        ["scan", str(project), "--out", str(out), "--supplier-cbom", str(supplier), "--json"],
    )

    assert result.exit_code == 0, result.output
    reconciliation_path = out / "supplier-reconciliation.json"
    assert reconciliation_path.exists()
    assert json.loads(reconciliation_path.read_text())["only_in_supplier"] == ["ML-KEM"]
