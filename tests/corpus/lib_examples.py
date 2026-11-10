# More library coverage examples
# OpenSSL-style
# EVP_PKEY_ML_KEM / NID_ML_KEM
# liboqs
# OQS_KEM_alg_ml_kem_768
# Java
# KeyPairGenerator.getInstance("ML-KEM")
# Go CIRCL
# circl/kem/mlkem

from oqs import KeyEncapsulation
kem = KeyEncapsulation("ML-KEM-768")
