"""Simple pattern-based cryptographic scanner for MVP.
Covers common APIs in Python, JavaScript, Java, Go, and config files.
"""

import re
from pathlib import Path
from typing import Iterator

from .models import Finding, QuantumStatus
from .certs import inspect_pem

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
    # === Python stdlib ===
    (r"hashlib\.md5\b", "MD5", QuantumStatus.WEAK, True, "hash"),
    (r"hashlib\.sha1\b", "SHA-1", QuantumStatus.WEAK, True, "hash"),
    (r"hashlib\.sha256\b", "SHA-256", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.sha512\b", "SHA-512", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    (r"hashlib\.blake2", "BLAKE2", QuantumStatus.SAFE_SYMMETRIC, False, "hash"),
    # === Java / Kotlin ===
    (r'Cipher\.getInstance\s*\(\s*"AES/ECB', "AES-ECB", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r'Cipher\.getInstance\s*\(\s*"AES/GCM', "AES-GCM", QuantumStatus.SAFE_SYMMETRIC, False, "encrypt"),
    (r'Cipher\.getInstance\s*\(\s*"RSA', "RSA", QuantumStatus.VULNERABLE, False, "encrypt"),
    (r'Cipher\.getInstance\s*\(\s*"DES', "DES", QuantumStatus.WEAK, True, "encrypt"),
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
    (r"KexAlgorithms\s+.*(?:diffie-hellman|ecdh|curve25519)", "DH/ECDH", QuantumStatus.VULNERABLE, False, "kex"),
    (r"HostKeyAlgorithms\s+.*(?:ssh-rsa|ecdsa)", "RSA/ECDSA", QuantumStatus.VULNERABLE, False, "hostkey"),
    (r"ssl_protocols\s+.*TLSv1\.[01]", "TLS1.0/1.1", QuantumStatus.WEAK, True, "protocol"),
    (r"MinProtocol\s*=\s*TLSv1\.[01]", "TLS1.0/1.1", QuantumStatus.WEAK, True, "protocol"),
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
    (r"x25519.*ml-?kem|ml-?kem.*x25519|x25519kyber|mlkem768x25519", "Hybrid-KEM", QuantumStatus.HYBRID, False, "kem"),
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
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".so", ".dll", ".exe"}


def scan_path(root: Path) -> Iterator[Finding]:
    """Scan a directory tree for cryptographic patterns."""
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
        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip pure comments and empty lines to reduce false positives
            # Do not skip PEM headers (-----BEGIN...)
            if not stripped:
                continue
            if stripped.startswith(("#", "//", "/*", "*")) and not stripped.startswith("-----"):
                continue
            if stripped.startswith("--") and not stripped.startswith("-----"):
                continue
            # Skip lines that are only documentation strings mentioning algorithms
            if stripped.startswith(('"""', "'''", '"', "'")) and any(
                kw in stripped.lower() for kw in ("example", "do not", "comment", "documentation")
            ):
                continue

            # Remove inline comments before matching (Python/JS style)
            code_part = line
            if "#" in code_part and not code_part.strip().startswith("-----"):
                code_part = code_part.split("#", 1)[0]
            if "//" in code_part:
                code_part = code_part.split("//", 1)[0]
            if not code_part.strip():
                continue

            for regex, family, status, weak, role in COMPILED:
                if regex.search(code_part):
                    finding_id += 1
                    snippet = line.strip()[:200]
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
                    )
        # Additional structured inspection for certificates / keys
        if path.suffix.lower() in {".pem", ".crt", ".cer", ".key"} or "BEGIN CERTIFICATE" in text or "PRIVATE KEY" in text:
            for extra in inspect_pem(path, root):
                finding_id += 1
                extra.id = f"QCI-{finding_id:04d}"
                yield extra
