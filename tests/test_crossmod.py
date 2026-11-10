from qci_pqc.crossmod import collect_constants

def test_constant_from_other_file(tmp_path):
    (tmp_path / "Alg.java").write_text('class A { static final String ALG = "AES/GCM"; }')
    (tmp_path / "Use.java").write_text('class U { void m() { Cipher.getInstance(ALG); } }')
    assert collect_constants(tmp_path)["ALG"] == "AES/GCM"
