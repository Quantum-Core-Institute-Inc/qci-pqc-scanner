# Expanded calibration — OpenSSL-style and hybrid
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib

def ecdsa_key():
    return ec.generate_private_key(ec.SECP256R1())

def sha1_legacy():
    return hashlib.sha1(b"old").hexdigest()

HYBRID = "X25519MLKEM768"
SIG = "ML-DSA-87"
