"""Simple pattern-based cryptographic scanner for MVP.
Covers common APIs in Python, JavaScript, Java, Go, and config files.
"""

import re
from pathlib import Path
from typing import Iterator

from .models import Finding, QuantumStatus
from .certs import inspect_pem
from .deps import scan_dependencies
from .resolve import resolve_configs, resolve_calls_and_maps, resolve_wiring

# Patterns: (regex, family, quantum_status, classical_weak, role)
PATTERNS = [
    # === Python cryptography / PyCA ===
    (r"rsa\.generate_private_key", "RSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"ec\.generate_private_key", "ECDSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"ed25519\.Ed25519PrivateKey", "Ed25519", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"x25519\.X25519PrivateKey", "X25519", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"hashes\.SHA1\b", "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r"hashes\.MD5\b", "MD5", QuantumStatus.WEAK, True, "hash"),
    (r"hashes\.SHA256\b", "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashes\.SHA512\b", "SHA-512", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"AES\.new\s*\([^)]*MODE_ECB", "AES-ECB", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r"AES\.new\s*\([^)]*MODE_GCM", "AES-GCM", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r"ChaCha20Poly1305", "ChaCha20-Poly1305", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),

    # === Missed common APIs (testbench batch 1) ===
    (r"Ed25519PrivateKey\.generate\(", "Ed25519", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"algorithms\.AES\b|AESGCM\b|aead\.AESGCM", "AES-GCM", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r"algorithms\.AES\([^)]*ECB|MODE_ECB", "AES-ECB", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r"(?<!ML-)\bDSA\b|dsa\.generate_private_key|KeyPairGenerator\.getInstance\(\s*\"DSA", "DSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"\bDH\b|dh\.generate_parameters|KeyAgreement\.getInstance\(\s*\"DH", "DH", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"HMAC\b|hmac\.new\b|Mac\.getInstance\(\s*\"Hmac", "HMAC", QuantumStatus.SAFE_SYMMETRIC, False, "mac"),
    (r"PBKDF2|pbkdf2_hmac|PBEKeySpec", "PBKDF2", QuantumStatus.SAFE_SYMMETRIC, False, "kdf"),
    (r"hashlib\.sha3_|SHA3-|SHA-3|hashes\.SHA3_", "SHA-3", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"X25519MLKEM768|X25519Kyber768Draft00|x25519_mlkem768", "X25519MLKEM768", QuantumStatus.HYBRID, False, "kem"),

    # Tier 1 API names without module prefix
    (r"\bEd25519PrivateKey\b", "Ed25519", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"\bX25519PrivateKey\b", "X25519", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"\bAESGCM\b", "AES-GCM", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r"\bTripleDES\b", "3DES", QuantumStatus.WEAK, True, "encrypt"),
    (r"modes\.ECB\b", "AES-ECB", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r"modes\.GCM\b", "AES-GCM", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r"PBKDF2HMAC|pbkdf2_hmac", "PBKDF2", QuantumStatus.SAFE_SYMMETRIC, False, "kdf"),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"X25519"', "X25519", QuantumStatus.VULNERABLE, False, "keygen"),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"DH"', "DH", QuantumStatus.VULNERABLE, False, "keygen"),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"DSA"', "DSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"SecP384r1MLKEM1024|mlkem768x25519|sntrup761x25519", "Named-Hybrid", QuantumStatus.HYBRID, False, "kem"),

    (r"Cipher\.getInstance\s*\(\s*\"DESede", "3DES", QuantumStatus.WEAK, True, "encrypt"),
    (r"hashes\.SHA1\b|SHA1\b", "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r"MessageDigest\.getInstance\s*\(\s*\"MD5", "MD5", QuantumStatus.WEAK, True, "hash"),
    (r"MessageDigest\.getInstance\s*\(\s*\"SHA-1", "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r"MessageDigest\.getInstance\s*\(\s*\"SHA-256", "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),

    (r"hashlib\.sha3_256|MessageDigest\.getInstance\s*\(\s*\"SHA3-256\"", "SHA-3", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"ssl_protocols\s+.*TLSv1(?:\s|;|$)|ssl_protocols\s+.*TLSv1\.0", "TLS-1.0", QuantumStatus.VULNERABLE, True, "protocol"),
    (r"ssl_protocols\s+.*TLSv1\.1", "TLS-1.1", QuantumStatus.VULNERABLE, True, "protocol"),
    (r"ssl_protocols\s+.*TLSv1\.2", "TLS-1.2", QuantumStatus.SAFE_SYMMETRIC, False, "protocol"),
    (r"ssl_ciphers\s+.*(?:AES128-GCM|ECDHE-RSA-AES128-GCM|AES256-SHA|DES-CBC3)", "AES", QuantumStatus.SAFE_SYMMETRIC, False, "cipher"),
    (r"ssl_ciphers\s+.*DES-CBC3", "3DES", QuantumStatus.WEAK, True, "cipher"),
    (r"hashlib\.sha224|hashes\.SHA224|MessageDigest\.getInstance\s*\(\s*\"SHA-224\"", "SHA-224", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.sha384|hashes\.SHA384|MessageDigest\.getInstance\s*\(\s*\"SHA-384\"", "SHA-384", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.sha3_384|SHA3-384", "SHA3-384", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.sha3_512|SHA3-512", "SHA3-512", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.shake_128|SHAKE128|shake128", "SHAKE128", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.shake_256|SHAKE256|shake256", "SHAKE256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"ripemd160|RIPEMD-160|RIPEMD160", "RIPEMD-160", QuantumStatus.WEAK, True, "hash"),
    (r"blake3|BLAKE3", "BLAKE3", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"\bSM2\b|sm2\.generate", "SM2", QuantumStatus.VULNERABLE, False, "sign"),
    (r"\bSM3\b|sm3\.digest|MessageDigest\.getInstance\s*\(\s*\"SM3\"", "SM3", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"\bSM4\b|sm4\.encrypt|Cipher\.getInstance\s*\(\s*\"SM4", "SM4", QuantumStatus.SAFE_SYMMETRIC, False, "cipher"),

    (r"hashlib\.new\s*\(\s*[\"']sha256[\"']|MessageDigest\.getInstance\s*\(\s*\"SHA256\"", "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.new\s*\(\s*[\"']sha512[\"']|MessageDigest\.getInstance\s*\(\s*\"SHA-?512\"", "SHA-512", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"sha512\.New\b|crypto\.createHash\s*\(\s*['\"]sha512['\"]", "SHA-512", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"Cipher\.getInstance\s*\(\s*\"AES/(ECB|GCM|CBC)", "AES", QuantumStatus.SAFE_SYMMETRIC, False, "cipher"),
    (r"digestmod\s*=\s*[\"']sha1[\"']", "HMAC", QuantumStatus.WEAK, True, "mac"),

    # === Go stdlib ===
    (r"md5\.Sum\b|crypto/md5", "MD5", QuantumStatus.WEAK, True, "hash"),
    (r"sha1\.Sum\b|crypto/sha1", "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r"sha256\.Sum256|sha256\.New\b|crypto/sha256", "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"sha512\.Sum512|crypto/sha512", "SHA-512", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"sha3\.|crypto/sha3", "SHA-3", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"aes\.NewCipher|crypto/aes", "AES", QuantumStatus.SAFE_SYMMETRIC, False, "cipher"),
    (r"rsa\.GenerateKey|crypto/rsa", "RSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"ecdsa\.GenerateKey|elliptic\.P256|crypto/ecdsa", "ECDSA", QuantumStatus.VULNERABLE, False, "sign"),
    (r"ed25519\.GenerateKey|crypto/ed25519", "Ed25519", QuantumStatus.VULNERABLE, False, "sign"),
    (r"ecdh\.X25519|crypto/ecdh", "X25519", QuantumStatus.VULNERABLE, False, "kex"),
    (r"des\.NewTripleDESCipher|crypto/des", "3DES", QuantumStatus.WEAK, True, "cipher"),
    (r"rc4\.NewCipher|crypto/rc4", "RC4", QuantumStatus.WEAK, True, "cipher"),
    (r"hmac\.New\b|crypto/hmac", "HMAC", QuantumStatus.SAFE_SYMMETRIC, False, "mac"),
    # === Python stdlib ===
    (r"hashlib\.md5\b", "MD5", QuantumStatus.WEAK, True, "hash"),
    (r"hashlib\.sha1\b", "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r'hashlib\.new\s*\(\s*["\']sha1["\']', "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r"hashlib\.sha256\b", "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.sha512\b", "SHA-512", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.blake2", "BLAKE2", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    # === Java / Kotlin ===
    (r'Cipher\.getInstance\s*\(\s*"AES/ECB', "AES", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r'Cipher\.getInstance\s*\(\s*"AES/GCM', "AES-GCM", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r'Cipher\.getInstance\s*\(\s*"RSA', "RSA", QuantumStatus.VULNERABLE, False, "encrypt"),
    (r'Cipher\.getInstance\s*\(\s*"DES(?!ede)', "DES", QuantumStatus.WEAK, True, "encrypt"),
    (r'Cipher\.getInstance\s*\(\s*"DESede', "3DES", QuantumStatus.WEAK, True, "encrypt"),
    (r'Signature\.getInstance\s*\(\s*"SHA256withRSA', "RSA", QuantumStatus.VULNERABLE, False, "sign"),
    (r'Signature\.getInstance\s*\(\s*"SHA1withRSA', "RSA", QuantumStatus.VULNERABLE, False, "sign"),
    (r'Signature\.getInstance\s*\(\s*"SHA256withECDSA', "ECDSA", QuantumStatus.VULNERABLE, False, "sign"),
    (r'Signature\.getInstance\s*\(\s*"Ed25519', "Ed25519", QuantumStatus.VULNERABLE, False, "sign"),
    (r'MessageDigest\.getInstance\s*\(\s*"MD5', "MD5", QuantumStatus.WEAK, True, "hash"),
    (r'MessageDigest\.getInstance\s*\(\s*"SHA-1', "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r'MessageDigest\.getInstance\s*\(\s*"SHA-256', "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"RSA', "RSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"EC', "ECDSA", QuantumStatus.VULNERABLE, False, "keygen"),
    # === Go ===
    (r"rsa\.GenerateKey", "RSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"ecdsa\.GenerateKey", "ECDSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"ed25519\.GenerateKey", "Ed25519", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"sha1\.New\b", "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r"md5\.New\b", "MD5", QuantumStatus.WEAK, True, "hash"),
    (r"sha256\.New\b", "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"aes\.NewCipher", "AES", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    # === JavaScript / Node / WebCrypto ===
    (r"crypto\.createSign\s*\(\s*['\"]RSA-", "RSA", QuantumStatus.VULNERABLE, False, "sign"),
    (r"crypto\.createSign\s*\(\s*['\"]sha256", "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "sign"),
    (r"crypto\.createHash\s*\(\s*['\"]sha1['\"]", "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r"crypto\.createHash\s*\(\s*['\"]md5['\"]", "MD5", QuantumStatus.WEAK, True, "hash"),
    (r"crypto\.createHash\s*\(\s*['\"]sha256['\"]", "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"subtle\.generateKey\s*\(\s*\{\s*name:\s*['\"]RSA-", "RSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"subtle\.generateKey\s*\(\s*\{\s*name:\s*['\"]ECDSA", "ECDSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"subtle\.generateKey\s*\(\s*\{\s*name:\s*['\"]ECDH", "ECDH", QuantumStatus.VULNERABLE, False, "keygen"),
    # === C / OpenSSL ===
    (r"EVP_PKEY_RSA", "RSA", QuantumStatus.VULNERABLE, False, "key"),
    (r"EVP_PKEY_EC", "ECDSA", QuantumStatus.VULNERABLE, False, "key"),
    (r"EVP_sha1\b", "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r"EVP_md5\b", "MD5", QuantumStatus.WEAK, True, "hash"),
    (r"EVP_aes_256_gcm", "AES-GCM", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r"RSA_generate_key", "RSA", QuantumStatus.VULNERABLE, False, "keygen"),
    # === Config / PEM / SSH / TLS ===
    (r"-----BEGIN RSA PRIVATE KEY-----", "RSA", QuantumStatus.VULNERABLE, False, "key"),
    (r"-----BEGIN EC PRIVATE KEY-----", "ECDSA", QuantumStatus.VULNERABLE, False, "key"),
    (r"-----BEGIN PRIVATE KEY-----", "PKCS8", QuantumStatus.UNKNOWN, False, "key"),
    (r"KexAlgorithms\s+.*curve25519", "X25519", QuantumStatus.VULNERABLE, False, "kex"),
    (r"KexAlgorithms\s+.*diffie-hellman", "DH", QuantumStatus.VULNERABLE, False, "kex"),
    (r"KexAlgorithms\s+.*ecdh", "ECDH", QuantumStatus.VULNERABLE, False, "kex"),
    (r"HostKeyAlgorithms\s+.*ssh-rsa", "RSA", QuantumStatus.VULNERABLE, False, "hostkey"),
    (r"HostKeyAlgorithms\s+.*ecdsa", "ECDSA", QuantumStatus.VULNERABLE, False, "hostkey"),
    (r"ssl_protocols\s+.*TLSv1\.[01]", "TLS1.0/1.1", QuantumStatus.WEAK, True, "protocol"),
    (r"MinProtocol\s*=\s*TLSv1\.[01]", "TLS1.0/1.1", QuantumStatus.WEAK, True, "protocol"),

    # PQC asset configs — name the group on the line
    (r"ssl_ecdh_curve\s+.*X25519MLKEM768|Groups\s*=\s*.*X25519MLKEM768", "X25519MLKEM768", QuantumStatus.HYBRID, False, "kem"),
    (r"Groups\s*=\s*.*SecP384r1MLKEM1024", "SecP384r1MLKEM1024", QuantumStatus.HYBRID, False, "kem"),
    (r"KexAlgorithms\s+.*mlkem768x25519", "X25519MLKEM768", QuantumStatus.HYBRID, False, "kex"),
    (r"sntrup761x25519", "sntrup761x25519", QuantumStatus.HYBRID, False, "kex"),
    (r"ssl_protocols\s+.*TLSv1\.3|MinProtocol\s*=\s*TLSv1\.3", "TLS-1.3", QuantumStatus.SAFE_SYMMETRIC, False, "protocol"),
    (r"Ciphers\s+.*chacha20-poly1305", "ChaCha20-Poly1305", QuantumStatus.SAFE_SYMMETRIC, False, "cipher"),

    # Classical companions on the same hybrid/config line
    (r"ssl_ecdh_curve\s+\S*X25519(?:[:\s;]|$)", "X25519", QuantumStatus.VULNERABLE, False, "kex"),
    (r"ssl_ecdh_curve\s+.*prime256v1|Groups\s*=\s*.*prime256v1|secp256r1", "ECC-P-256", QuantumStatus.VULNERABLE, False, "kex"),
    (r"Groups\s*=\s*.*secp384r1|ssl_ecdh_curve\s+.*secp384r1", "ECC-P-384", QuantumStatus.VULNERABLE, False, "kex"),
    # === PQC / Hybrid (NIST FIPS 203/204/205 + others) ===
    # ML-KEM (FIPS 203, formerly Kyber)
    (r"\bml-?kem-?512\b|\bkyber512\b", "ML-KEM-512", QuantumStatus.PQC, False, "kem"),
    (r"\bml-?kem-?768\b|\bkyber768\b", "ML-KEM-768", QuantumStatus.PQC, False, "kem"),
    (r"\bml-?kem-?1024\b|\bkyber1024\b", "ML-KEM-1024", QuantumStatus.PQC, False, "kem"),
    (r"\bml-?kem\b|\bkyber\b", "ML-KEM", QuantumStatus.PQC, False, "kem"),
    # ML-DSA (FIPS 204, formerly Dilithium)
    (r"\bml-?dsa-?44\b|\bdilithium2\b", "ML-DSA-44", QuantumStatus.PQC, False, "sign"),
    (r"\bml-?dsa-?65\b|\bdilithium3\b", "ML-DSA-65", QuantumStatus.PQC, False, "sign"),
    (r"\bml-?dsa-?87\b|\bdilithium5\b", "ML-DSA-87", QuantumStatus.PQC, False, "sign"),
    (r"\bml-?dsa\b|\bmldsa\b|\bdilithium\b", "ML-DSA", QuantumStatus.PQC, False, "sign"),
    # SLH-DSA (FIPS 205, formerly SPHINCS+)
    (r"\bslh-?dsa\b|\bslhdsa\b|\bsphincs\+?\b|slhdsa_", "SLH-DSA", QuantumStatus.PQC, False, "sign"),
    # FN-DSA (FIPS 206 draft, formerly Falcon)
    (r"\bfn-?dsa\b|\bfalcon\b", "FN-DSA", QuantumStatus.PQC, False, "sign"),
    # Other candidates / backups
    (r"\bhqc\b", "HQC", QuantumStatus.PQC, False, "kem"),
    (r"\bclassic\s*mceliece\b|\bmceliece\b", "Classic-McEliece", QuantumStatus.PQC, False, "kem"),
    (r"\bbike\b", "BIKE", QuantumStatus.PQC, False, "kem"),
    # Hybrids
    (r"X25519MLKEM768|x25519.*ml-?kem|mlkem768x25519", "X25519MLKEM768", QuantumStatus.HYBRID, False, "kem"),
    (r"secp256r1.*ml-?dsa|ml-?dsa.*secp256r1", "Hybrid-Sign", QuantumStatus.HYBRID, False, "sign"),
    # === More library / API patterns ===
    # OpenSSL / libcrypto style
    (r"EVP_PKEY_RSA|NID_rsaEncryption|RSA_generate_key", "RSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"EVP_PKEY_EC|NID_X9_62_id_ecPublicKey|EC_KEY_generate_key", "ECDSA", QuantumStatus.VULNERABLE, False, "keygen"),
    (r"OSSL_PKEY_PARAM_ML_KEM|EVP_PKEY_ML_KEM|NID_ML_KEM", "ML-KEM", QuantumStatus.PQC, False, "kem"),
    (r"OSSL_PKEY_PARAM_ML_DSA|EVP_PKEY_ML_DSA|NID_ML_DSA", "ML-DSA", QuantumStatus.PQC, False, "sign"),
    # liboqs
    (r"OQS_KEM_alg_ml_kem|OQS_SIG_alg_ml_dsa|oqs\.KeyEncapsulation", "liboqs-PQC", QuantumStatus.PQC, False, "pqc"),
    # Java BouncyCastle / JCA
    (r"MLKEMParameterSpec|MLDSAParameterSpec|SPHINCSPlusParameterSpec", "Java-PQC", QuantumStatus.PQC, False, "pqc"),
    (r"KeyPairGenerator\.getInstance\(\"ML-KEM\"|\"ML-DSA\"|\"SLH-DSA\"", "Java-PQC", QuantumStatus.PQC, False, "pqc"),
    # Go
    (r"circl/kem/mlkem|circl/sign/mldsa|circl/sign/slhdsa", "Go-CIRCL-PQC", QuantumStatus.PQC, False, "pqc"),
    # BoringSSL / AWS-LC style (similar to OpenSSL)
    (r"EVP_PKEY_KYBER|NID_KYBER", "Kyber-prestandard", QuantumStatus.PQC, False, "kem"),
    # === Hybrid validation helpers ===
    (r"hybrid.*(?:ml-?kem|ml-?dsa)|(?:ml-?kem|ml-?dsa).*hybrid", "Hybrid-PQC", QuantumStatus.HYBRID, False, "hybrid"),
    (r"x25519mlkem|p256_mlkem|secp256r1_mldsa", "Hybrid-Named", QuantumStatus.HYBRID, False, "hybrid"),
    # === Certificates & TLS / SSH configs ===
    (r"-----BEGIN CERTIFICATE-----", "X509-Cert", QuantumStatus.UNKNOWN, False, "cert"),
    (r"-----BEGIN RSA PRIVATE KEY-----|-----BEGIN EC PRIVATE KEY-----", "Private-Key", QuantumStatus.VULNERABLE, False, "key"),
    # nginx / Apache
    (r"ssl_certificate\s+|SSLCertificateFile|ssl_certificate_key", "TLS-Cert-Config", QuantumStatus.UNKNOWN, False, "config"),
    (r"ssl_protocols\s+.*TLSv1\.[01]|SSLProtocol\s+.*TLSv1\.[01]", "TLS-Weak-Protocol", QuantumStatus.WEAK, True, "protocol"),
    (r"ssl_ciphers\s+.*(?:RC4|DES|3DES|NULL|EXPORT|MD5)", "TLS-Weak-Cipher", QuantumStatus.WEAK, True, "cipher"),
    (r"ssl_ciphers\s+.*(?:ECDHE|DHE).*AES", "TLS-Classical-Cipher", QuantumStatus.VULNERABLE, False, "cipher"),
    # OpenSSL config
    (r"MinProtocol\s*=\s*TLSv1\.[01]|CipherString\s*=.*DEFAULT", "OpenSSL-Config", QuantumStatus.WEAK, True, "config"),
    # sshd_config — weak KEX
    (r"KexAlgorithms\s+.*(?:diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)", "SSH-Weak-Kex", QuantumStatus.WEAK, True, "kex"),
    (r"KexAlgorithms\s+.*diffie-hellman-group14-sha256", "SSH-Legacy-Kex", QuantumStatus.WEAK, True, "kex"),
    # sshd_config — classical (quantum-vulnerable) KEX
    (r"KexAlgorithms\s+.*(?:curve25519-sha256|ecdh-sha2-nistp|diffie-hellman-group16|diffie-hellman-group18)", "SSH-Classical-Kex", QuantumStatus.VULNERABLE, False, "kex"),
    # sshd_config — weak ciphers
    (r"Ciphers\s+.*(?:3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|blowfish-cbc|cast128-cbc)", "SSH-Weak-Cipher", QuantumStatus.WEAK, True, "cipher"),
    (r"Ciphers\s+.*(?:chacha20-poly1305|aes128-gcm|aes256-gcm|aes128-ctr|aes256-ctr)", "SSH-Modern-Cipher", QuantumStatus.SAFE_SYMMETRIC, False, "cipher"),
    # sshd_config — weak MACs
    (r"MACs\s+.*(?:hmac-md5|hmac-sha1|hmac-sha1-96|umac-64)", "SSH-Weak-MAC", QuantumStatus.WEAK, True, "mac"),
    # Host keys
    (r"HostKeyAlgorithms\s+.*(?:ssh-rsa|ssh-dss|ecdsa-sha2)", "SSH-Classical-HostKey", QuantumStatus.VULNERABLE, False, "hostkey"),
    (r"HostKeyAlgorithms\s+.*ssh-ed25519", "SSH-Ed25519-HostKey", QuantumStatus.VULNERABLE, False, "hostkey"),
    # PQC hybrid
    (r"KexAlgorithms\s+.*(?:sntrup761|mlkem|kyber)", "SSH-PQC-Kex", QuantumStatus.HYBRID, False, "kex"),
    # Java security properties
    (r"jdk\.tls\.disabledAlgorithms|jdk\.certpath\.disabledAlgorithms", "Java-TLS-Policy", QuantumStatus.UNKNOWN, False, "config"),
    # Dependency hints
    (r"liboqs|oqs-python|bouncycastle.*pqc|circl", "PQC-Dependency", QuantumStatus.PQC, False, "dependency"),
]


COMPILED = [(re.compile(pat, re.IGNORECASE), fam, status, weak, role) for pat, fam, status, weak, role in PATTERNS]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "target"}
PROJECT_CONSTS: dict[str, str] = {}
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".so", ".dll", ".exe", ".md", ".rst"}




def _int_constants(lines: list[str]) -> dict[str, str]:
    consts = {}
    pat = re.compile(r"([A-Z_][A-Z0-9_]*)\s*=\s*(\d{3,5})\b")
    for line in lines:
        for m in pat.finditer(line):
            consts[m.group(1)] = m.group(2)
    return consts


def _string_constants(lines: list[str]) -> dict[str, str]:
    """Find string constants, supported defaults, and enum constructor values."""
    consts = {}
    assign = re.compile(
        r"(?:(?:public|private|static|final)\s+)*String\s+([A-Z_][A-Z0-9_]*)\s*=\s*[\"']([^\"']+)[\"']"
        r"|([A-Z_][A-Z0-9_]*)\s*=\s*[\"']([^\"']+)[\"']"
        r"|([A-Z_][A-Z0-9_]*)\s*=\s*os\.environ\.get\(\s*[\"'][^\"']+[\"']\s*,\s*[\"']([^\"']+)[\"']"
        r"|([A-Z_][A-Z0-9_]*)\s*=\s*System\.getProperty\(\s*[\"'][^\"']+[\"']\s*,\s*[\"']([^\"']+)[\"']"
    )
    enum = re.compile(r"([A-Z_][A-Z0-9_]*)\s*\(\s*[\"']([^\"']+)[\"']\s*\)")
    for line in lines:
        for m in assign.finditer(line):
            name = m.group(1) or m.group(3) or m.group(5) or m.group(7)
            val = m.group(2) or m.group(4) or m.group(6) or m.group(8)
            if name and val:
                consts[name] = val
        for m in enum.finditer(line):
            consts[m.group(1)] = m.group(2)
    return consts


def _expand_constants(line: str, consts: dict[str, str]) -> str:
    if not consts:
        return line
    # Do not rewrite the definition line itself.
    if re.search(r"^\s*(?:(?:public|private|static|final)\s+)*String\s+[A-Z_]", line) or re.search(r"^\s*[A-Z_][A-Z0-9_]*\s*=", line):
        return line
    out = line
    for name, val in consts.items():
        if name in out:
            out = re.sub(rf"(?:\w+\.)?\b{name}\b(?:\.\w+)*", f'\"{val}\"', out)
    # Collapse "A" + "/" + "B" into "A/B" so DESede/CBC matches.
    out = re.sub(r'"([^"]+)"\s*\+\s*"/"\s*\+\s*"([^"]+)"(?:\s*\+\s*"/"\s*\+\s*"([^"]+)")?',
                 lambda m: '"' + "/".join(p for p in m.groups() if p) + '"', out)
    return out


def _alias_map(lines: list[str]) -> dict[str, str]:
    aliases = {}
    for line in lines:
        m = re.search(r"import\s+([\w.]+)\s+as\s+(\w+)", line)
        if m:
            aliases[m.group(2)] = m.group(1).split(".")[-1]
    return aliases


def scan_path(root: Path) -> Iterator[Finding]:
    """Scan a directory tree for cryptographic patterns."""
    global PROJECT_CONSTS
    PROJECT_CONSTS = {}
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".py", ".java", ".kt"} and not any(part in SKIP_DIRS for part in path.parts):
            try:
                PROJECT_CONSTS.update(_string_constants(path.read_text(encoding="utf-8", errors="ignore").splitlines()))
            except Exception:
                continue
    finding_id = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_EXTS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        lines = text.splitlines()
        consts = {**PROJECT_CONSTS, **_string_constants(lines), **_int_constants(lines)}
        aliases = _alias_map(lines)
        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip pure comments and empty lines to reduce false positives
            # Do not skip PEM headers (-----BEGIN...)
            if not stripped:
                continue
            if stripped.startswith(("#", "//", "/*", "*", '"""', "'''")) and not stripped.startswith("-----"):
                continue
            if stripped.startswith("--") and not stripped.startswith("-----"):
                continue
            # Skip lines that are only documentation strings mentioning algorithms
            if stripped.startswith(('"""', "'''", '"', "'")) and any(
                kw in stripped.lower() for kw in ("example", "do not", "comment", "documentation")
            ):
                continue

            if line.strip().startswith("import ") or line.strip().startswith("from "):
                continue
            # String catalogs ("sha1": "SHA-1 (deprecated)") are labels, not usage.
            if re.search(r"""^\s*['"][a-z0-9_-]+['"]\s*:""", line):
                continue
            if re.search(r"log\.(warning|info|debug)|logger\.", line):
                continue
            if re.search(r"""==\s*['"]sha1['"]|==\s*['"]md5['"]|==\s*['"]dsa['"]""", line, re.I):
                continue
            # Remove inline comments before matching (Python/JS style)
            code_part = _expand_constants(line, consts)
            for alias, real in aliases.items():
                code_part = re.sub(rf"\b{alias}\.", real + ".", code_part)
            if "#" in code_part and not code_part.strip().startswith("-----"):
                code_part = code_part.split("#", 1)[0]
            if "//" in code_part:
                code_part = code_part.split("//", 1)[0]
            if not code_part.strip():
                continue

            for regex, family, status, weak, role in COMPILED:
                if regex.search(code_part):
                    # Drop PQC names in comments and string catalogs; keep calls, assignments, imports, configs.
                    if status in (QuantumStatus.PQC, QuantumStatus.HYBRID):
                        low = code_part.lower().strip()
                        if low.startswith(("#", "//", "/*", "*")):
                            continue
                        if "list.of" in low or low.startswith(('"', "'")):
                            continue
                        # Display strings: char notes[] = {"ML-KEM ..."} or ["ML-KEM-768"]
                        if re.search(r"=\s*[\[{]\s*[\"']", code_part):
                            continue
                        if not any(tok in low for tok in ("import", "=", "(", "groups", "kexalgorithms", "ssl_ecdh")):
                            continue
                        # Prefer the concrete level when the file names one.
                        if family == "ML-KEM":
                            lvl = re.search(r"LEVEL\s*=\s*(512|768|1024)", text)
                            if lvl:
                                family = f"ML-KEM-{lvl.group(1)}"
                        if family == "ML-DSA":
                            lvl = re.search(r"LEVEL\s*=\s*(44|65|87)", text)
                            if lvl:
                                family = f"ML-DSA-{lvl.group(1)}"
                    finding_id += 1
                    snippet = line.strip()[:200]
                    category = ""
                    if family in {"X25519", "DH", "ECDH"} and role == "kex":
                        category = "DH/ECDH"
                    elif family in {"RSA", "ECDSA"} and role == "hostkey":
                        category = "RSA/ECDSA"
                    param = ""
                    if role in ("kem", "kex", "cipher", "protocol") or status == QuantumStatus.HYBRID:
                        param = family
                    if family == "TLS-1.3":
                        param = "TLSv1.3"
                    # Classical parameters from the same line.
                    ints = _int_constants(lines)
                    expanded = code_part
                    for name, val in ints.items():
                        expanded = re.sub(rf"\b{name}\b", val, expanded)
                    m = re.search(r"(?:key_size|KEY_BITS|keyBits|initialize)\s*[=(]\s*(\d{3,5})", expanded)
                    if m and family in {"RSA", "DSA", "ECDSA", "DH"}:
                        param = m.group(1)
                    curve = re.search(r"SECP(256|384|521)R1|prime256v1|secp256r1|secp384r1", text, re.I)
                    if curve and family in {"ECDSA", "ECDH", "ECC-P-256", "ECC-P-384"}:
                        bits = "256" if "256" in curve.group(0).upper() else ("384" if "384" in curve.group(0) else "521")
                        param = f"P-{bits}"
                    if param.upper().startswith("SECP") or param.upper().startswith("PRIME"):
                        if "256" in param:
                            param = "P-256"
                        elif "384" in param:
                            param = "P-384"
                    if family.startswith("AES"):
                        family = "AES"
                        size = ""
                        bits = re.search(r"bit_length\s*=\s*(\d+)", text)
                        init = re.search(r"\.init\s*\(\s*(\d{2,4})\s*\)", text)
                        ur = re.search(r"urandom\s*\(\s*(\d+)", text)
                        default_bits = re.search(r"getInteger\s*\([^,]+,\s*(\d{2,4})\s*\)", text)
                        if bits:
                            size = bits.group(1)
                        elif init:
                            size = init.group(1)
                        elif default_bits:
                            size = default_bits.group(1)
                        elif ur:
                            size = str(int(ur.group(1)) * 8)
                        elif param.isdigit():
                            size = param
                        mode = ""
                        if re.search(r"modes\.ECB|AES/ECB", text):
                            mode = "ECB"
                        elif re.search(r"AESGCM|modes\.GCM|AES/GCM", text):
                            mode = "GCM"
                        elif re.search(r"modes\.CBC|AES/CBC", text):
                            mode = "CBC"
                        param = "-".join(x for x in (size, mode) if x) or param
                    # Size on another line in the same file: kpg.initialize(3072)
                    if family in {"RSA", "DSA", "DH"} and not param:
                        init = re.search(r"\.initialize\s*\(\s*(\d{3,5})\s*\)", text)
                        bits = re.search(r"KEY_BITS\s*=\s*(\d{3,5})", text)
                        if init:
                            param = init.group(1)
                        elif bits:
                            param = bits.group(1)
                    if family in {"3DES", "DES"} and re.search(r"modes\.CBC|CBC", code_part):
                        param = "CBC"
                    if family in {"HMAC", "PBKDF2"} and re.search(r"sha256|SHA256", text, re.I):
                        param = "SHA-256"
                    if family == "HMAC" and re.search(r"digestmod\s*=\s*[\"']sha1[\"']|hmac-sha1", text, re.I):
                        param = "SHA-1"
                    yield Finding(
                        id=f"QCI-{finding_id:04d}",
                        evidence_path=str(path.relative_to(root)),
                        evidence_line=line_no,
                        evidence_snippet=snippet,
                        family=family,
                        quantum_status=status,
                        classical_weak=weak,
                        role=role,
                        source_scanner="qci-pattern",
                        confidence=0.85 if status in (QuantumStatus.VULNERABLE, QuantumStatus.PQC) else 0.7,
                        risk_category=category,
                        parameter_set=param,
                    )
        # Additional structured inspection for certificates / keys
        if path.suffix.lower() in {".pem", ".crt", ".cer", ".key"} or "BEGIN CERTIFICATE" in text or "PRIVATE KEY" in text:
            for extra in inspect_pem(path, root):
                finding_id += 1
                extra.id = f"QCI-{finding_id:04d}"
                yield extra

    for extra in resolve_configs(root) + resolve_calls_and_maps(root) + resolve_wiring(root):
        finding_id += 1
        extra.id = f"QCI-{finding_id:04d}"
        yield extra

    # Dependency → crypto capability mapping
    for dep in scan_dependencies(root):
        finding_id += 1
        dep.id = f"QCI-{finding_id:04d}"
        yield dep
