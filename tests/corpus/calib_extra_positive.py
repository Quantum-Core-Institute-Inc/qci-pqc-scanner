# Additional public-style calibration cases
# Positive: real usage that should be detected
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def use_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def use_md5():
    return hashlib.md5(b"legacy").hexdigest()

PQC = "ML-KEM-768"
SIG = "ML-DSA-65"
