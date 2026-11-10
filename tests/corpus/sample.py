# Corpus: RSA, ECDSA, weak hashes, safe hash, PQC mention
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import hashlib

def keys():
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec.generate_private_key(ec.SECP256R1())

def hashes():
    hashlib.md5(b"data")
    hashlib.sha1(b"data")
    hashlib.sha256(b"safe")

# Using mlkem for hybrid
mlkem_alg = "ML-KEM-768"
