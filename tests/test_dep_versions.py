from qci_pqc.deps import scan_dependencies

def test_pypi_version(tmp_path):
    (tmp_path / "requirements.txt").write_text("cryptography==42.0.5\n")
    hits = scan_dependencies(tmp_path)
    assert hits and hits[0].parameter_set == "42.0.5"

def test_npm_range_is_stripped(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"jsonwebtoken": "^9.0.2"}}')
    hits = [h for h in scan_dependencies(tmp_path) if h.family == "jsonwebtoken"]
    assert hits and hits[0].parameter_set == "9.0.2"

def test_go_sum_version(tmp_path):
    (tmp_path / "go.sum").write_text("golang.org/x/crypto v0.21.0 h1:abc\n")
    hits = scan_dependencies(tmp_path)
    assert hits and "0.21.0" in (hits[0].parameter_set or "")
