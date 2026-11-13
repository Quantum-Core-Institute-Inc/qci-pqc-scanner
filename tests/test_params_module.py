import textwrap
from qci_pqc import params
from qci_pqc.scanner import scan_path

def _refine(family, src, needle, param=""):
    lines = textwrap.dedent(src).strip("\n").splitlines()
    idx = next(i for i, line in enumerate(lines) if needle in line)
    return params.refine(family, param, lines, idx)

def test_go_rsa_size():
    assert _refine("RSA", "key, err := rsa.GenerateKey(rand.Reader, 4096)", "GenerateKey") == "4096"

def test_java_initialize_on_the_next_line():
    src = 'KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");\ngen.initialize(4096);'
    assert _refine("RSA", src, "getInstance") == "4096"

def test_two_definitions_mean_no_answer():
    src = "bits = 2048\nbits = 4096\nkey = RSA.generate(bits)"
    assert _refine("RSA", src, "RSA.generate") == ""

def test_aes_size_and_mode():
    src = 'const c = createCipheriv("aes-192-ctr", key, iv);'
    assert _refine("AES", src, "createCipheriv") == "192-CTR"

def test_end_to_end(tmp_path):
    (tmp_path / "main.go").write_text("package main\nfunc main() {\n    key, _ := rsa.GenerateKey(rand.Reader, 3072)\n}\n")
    hits = [f for f in scan_path(tmp_path) if f.family == "RSA"]
    assert any(f.parameter_set == "3072" for f in hits)
