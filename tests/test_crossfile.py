from qci_pqc.crossmod import collect_constants
from qci_pqc.scanner import scan_path

def test_c_define_is_collected(tmp_path):
    (tmp_path / "cfg.h").write_text('#define HASH_ALG "sha1"\n')
    consts = collect_constants(tmp_path)
    assert consts.get("HASH_ALG") == "sha1"

def test_js_const_is_collected(tmp_path):
    (tmp_path / "cfg.js").write_text('const CIPHER = "aes-256-gcm";\n')
    consts = collect_constants(tmp_path)
    assert consts.get("CIPHER") == "aes-256-gcm"

def test_crossfile_use(tmp_path):
    (tmp_path / "cfg.py").write_text('HASH_ALG = "sha1"\n')
    (tmp_path / "use.py").write_text('import hashlib\ndef f():\n    return hashlib.new(HASH_ALG)\n')
    hits = [h for h in scan_path(tmp_path) if h.family == "SHA-1" and h.evidence_path.endswith("use.py")]
    assert hits
