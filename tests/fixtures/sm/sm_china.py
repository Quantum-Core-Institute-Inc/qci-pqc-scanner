"""Chinese commercial cryptography: SM2 signature, SM3 hash, SM4 cipher."""
from gmssl import sm2, sm3, sm4

sm2_key = sm2.CryptSM2(public_key="04ab", private_key="ab")
sig = sm2_key.sign(b"invoice-4471")

digest = sm3.sm3_hash(list(b"payload"))

cipher = sm4.CryptSM4()
cipher.set_key(b"0123456789abcdef", sm4.SM4_ENCRYPT)
blob = cipher.crypt_ecb(b"0123456789abcdef")
