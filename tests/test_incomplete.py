import json
import zipfile

import pytest
from click.testing import CliRunner

from qci_pqc.adapters import get_adapter
from qci_pqc.cli import cli
from qci_pqc.coverage import reset, skip, summary

def test_a_skip_marks_partial():
    reset()
    skip("app.tar", "corrupt")
    assert summary()["partial"] is True
    assert summary()["skipped"] == ["app.tar: corrupt"]


@pytest.mark.parametrize("failure", ["unavailable", "failed"])
@pytest.mark.parametrize("adapters", ["broken,internal", "internal,broken", "broken"])
def test_skipped_adapter_marks_scan_partial(tmp_path, monkeypatch, failure, adapters):
    class BrokenAdapter:
        name = "broken"

        def available(self):
            return failure != "unavailable"

        def scan(self, root):
            raise RuntimeError("scan error")

    monkeypatch.setattr(
        "qci_pqc.cli.get_adapter",
        lambda name: BrokenAdapter() if name == "broken" else get_adapter(name),
    )
    project = tmp_path / "project"
    project.mkdir()
    out = tmp_path / "out"

    result = CliRunner().invoke(cli, ["scan", str(project), "--adapter", adapters, "--out", str(out)])

    reason = "adapter not available" if failure == "unavailable" else "adapter failed: scan error"
    assert result.exit_code == 1, result.output
    coverage = json.loads((out / "scan-coverage.json").read_text())
    assert coverage["partial"] is True
    assert coverage["skipped"] == [f"broken: {reason}"]
    assert "Incomplete scan: 1 skipped" in result.output


def test_scanned_archive_does_not_mark_scan_partial(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    with zipfile.ZipFile(project / "app.jar", "w") as archive:
        archive.writestr("App.class", b"\xca\xfe\xba\xbe" + b"\x00" * 16)
    out = tmp_path / "out"

    result = CliRunner().invoke(cli, ["scan", str(project), "--out", str(out)])

    assert result.exit_code == 0, result.output
    coverage = json.loads((out / "scan-coverage.json").read_text())
    assert coverage["partial"] is False
    assert coverage["skipped"] == []
