from pathlib import Path
from qci_pqc.artifacts import scan_artifacts, scan_images
from qci_pqc.coverage import reset, summary

CASES = [
    "Secret.class",
    "app.jar",
    "lib.whl",
    "libcrypto.so",
    "app.exe",
    "image.tar",
]

def test_no_artifact_type_is_read_outside_the_tree(tmp_path):
    reset()
    outside = tmp_path / "outside"
    outside.mkdir()
    tree = tmp_path / "tree"
    tree.mkdir()
    for name in CASES:
        target = outside / name
        target.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 16)
        (tree / name).symlink_to(target)
    hits = scan_artifacts(tree) + scan_images(tree)
    assert hits == []
    skipped = summary()["skipped"]
    for name in CASES:
        assert any(name in s and "leaves the tree" in s for s in skipped), name
