import zipfile
from pathlib import Path
from qci_pqc.artifacts import scan_artifacts
from qci_pqc.scanner import scan_path
from qci_pqc.coverage import reset, summary

def test_corrupt_nested_jar_is_recorded(tmp_path):
    reset()
    war = tmp_path / "app.war"
    with zipfile.ZipFile(war, "w") as zf:
        zf.writestr("lib/broken.jar", b"not a jar")
    scan_artifacts(tmp_path)
    assert any("corrupt nested" in s for s in summary()["skipped"])

def test_source_does_not_read_outside_the_tree(tmp_path, monkeypatch):
    reset()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "leak.py"
    secret.write_text("KEY = 'RSA'\n")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "leak.py").symlink_to(secret)
    opened = []
    real = Path.read_text
    def spy(self, *a, **k):
        opened.append(str(self))
        return real(self, *a, **k)
    monkeypatch.setattr(Path, "read_text", spy)
    list(scan_path(tree))
    assert not any("outside" in p for p in opened)
