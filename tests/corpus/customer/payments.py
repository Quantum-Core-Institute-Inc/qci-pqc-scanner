"""Shape from a payment service, not a testbench file."""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa

def seal(payload: bytes) -> bytes:
    return AESGCM(AESGCM.generate_key(bit_length=256)).encrypt(b"n"*12, payload, None)

def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
