# Example crypto usage for testing the scanner

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
import hashlib

def generate_keys():
    # Vulnerable
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())

    # Weak
    h1 = hashlib.md5(b"data")
    h2 = hashlib.sha1(b"data")

    # Safe
    h3 = hashlib.sha256(b"data")

    return private_key

# PQC mention
# Using mlkem for hybrid
