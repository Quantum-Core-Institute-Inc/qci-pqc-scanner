from pathlib import Path
from qci_pqc.artifacts import scan_artifacts

def test_out_of_tree_class_is_not_read(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Secret.class").write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 20)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "Secret.class").symlink_to(outside / "Secret.class")
    hits = scan_artifacts(tree)
    assert not any("Secret" in (f.evidence_snippet or "") for f in hits)
