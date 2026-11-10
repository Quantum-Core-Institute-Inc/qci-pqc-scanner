from qci_pqc.protector import protector, state

def test_kms():
    assert protector("key_id = aws_kms:alias/pay") == "kms"

def test_file():
    assert protector("-----BEGIN PRIVATE KEY-----") == "file"
    assert state("-----BEGIN PRIVATE KEY-----") == "active"
