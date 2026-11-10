# Labeled calibration cases
# POSITIVE: real crypto usage
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes

def real_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def real_ec():
    return ec.generate_private_key(ec.SECP256R1())

def real_weak():
    return hashlib.md5(b"x").hexdigest()

def real_pqc():
    # ML-KEM-768 reference
    return "ML-KEM-768"
