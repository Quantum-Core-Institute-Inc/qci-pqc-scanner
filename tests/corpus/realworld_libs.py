// Real-world style snippets: OpenSSL, liboqs, BouncyCastle, CIRCL, Python

// --- OpenSSL / libcrypto ---
// EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
// EVP_PKEY_keygen_init(ctx);
// NID_ML_KEM_768 / EVP_PKEY_ML_KEM (OpenSSL 3.5+)

// --- liboqs ---
// #include <oqs/oqs.h>
// OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
// OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

// --- Java BouncyCastle / JCA ---
// KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
// kpg.initialize(MLKEMParameterSpec.ml_kem_768);
// Signature sig = Signature.getInstance("ML-DSA");

// --- Go CIRCL ---
// import "github.com/cloudflare/circl/kem/mlkem"
// import "github.com/cloudflare/circl/sign/mldsa"
// scheme := mlkem.Scheme()

// --- Python (cryptography / oqs) ---
from oqs import KeyEncapsulation, Signature
kem = KeyEncapsulation("ML-KEM-768")
sig = Signature("ML-DSA-65")

// Classical still present
import rsa_example
# rsa.generate_private_key(public_exponent=65537, key_size=2048)
