# Negative / safe cases for false-positive control
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def safe():
    h = hashlib.sha256(b"ok")
    h = hashlib.sha384(b"ok")
    aes = AESGCM.generate_key(bit_length=256)
    # Comment only: rsa.generate_private_key should not fire if commented
    # rsa.generate_private_key(...)
    return h, aes
