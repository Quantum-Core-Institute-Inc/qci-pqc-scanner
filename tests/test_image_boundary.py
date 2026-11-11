from pathlib import Path
from qci_pqc.artifacts import scan_images
from qci_pqc.coverage import reset, summary

def test_linked_image_outside_tree_is_not_read(tmp_path):
    reset()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "image.tar").write_bytes(b"not a tar")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "image.tar").symlink_to(outside / "image.tar")
    hits = scan_images(tree)
    assert hits == []
    assert any("leaves the tree" in s for s in summary()["skipped"])
