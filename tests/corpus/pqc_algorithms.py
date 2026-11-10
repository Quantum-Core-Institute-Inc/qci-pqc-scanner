# Expanded PQC algorithm references for corpus testing
from pqc_lib import (
    MLKEM768,          # FIPS 203
    MLDSA65,           # FIPS 204
    SLHDSA_SHA2_128f,  # FIPS 205
    Falcon512,         # FN-DSA / FIPS 206 draft
)

# Parameter sets
kem = MLKEM768()
sig = MLDSA65()
hash_sig = SLHDSA_SHA2_128f()

# Hybrid
from hybrid import X25519Kyber768
hybrid = X25519Kyber768()

# Other
hqc = "HQC-128"
mceliece = "Classic McEliece"
