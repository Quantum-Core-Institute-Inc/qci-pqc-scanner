"""Map known dependencies to cryptographic capabilities.

Looks at requirements.txt, package.json, go.mod, pom.xml, and similar
files for library names/versions and reports what crypto they support.
"""

import re
from pathlib import Path

from .models import Finding, QuantumStatus

# library pattern -> (family, status, note, min_pqc_version or None)
LIBRARY_MAP = [
    (r"cryptography\s*[=<>~!]*\s*([\d.]+)?", "Python-cryptography", QuantumStatus.VULNERABLE,
     "ML-KEM and ML-DSA from 48.0.0 with OpenSSL 3.5.", "48.0"),
    (r"pyopenssl|pyOpenSSL", "pyOpenSSL", QuantumStatus.VULNERABLE,
     "Wraps OpenSSL. PQC depends on the linked OpenSSL version.", None),
    (r"oqs(?:-python)?|liboqs", "liboqs", QuantumStatus.PQC,
     "Provides ML-KEM, ML-DSA, SLH-DSA and hybrids.", None),
    (r"circl", "Go-CIRCL", QuantumStatus.PQC,
     "Cloudflare CIRCL: ML-KEM, ML-DSA, Kyber, Dilithium.", None),
    (r"bouncycastle[^\d]*([\d.]+)?", "BouncyCastle", QuantumStatus.VULNERABLE,
     "Final ML-KEM, ML-DSA, and SLH-DSA from 1.79.", "1.79"),
    (r"(?<!py)openssl\s*[=<>~]*\s*([\d.]+)?", "OpenSSL", QuantumStatus.VULNERABLE,
     "ML-KEM/ML-DSA available from OpenSSL 3.5+. Earlier versions are classical only.", "3.5"),

    (r"jsonwebtoken|crypto-js|node-forge|bcryptjs|@noble/post-quantum", "npm-crypto", QuantumStatus.VULNERABLE, "npm crypto package. Check maintenance and PQC support.", None),
    (r"PyCryptodome|pycryptodome", "PyCryptodome", QuantumStatus.VULNERABLE, "Classical ciphers and hashes.", None),

    (r"jsonwebtoken|crypto-js|node-forge|bcryptjs|@noble/post-quantum", "npm-crypto", QuantumStatus.VULNERABLE, "npm crypto package. Check maintenance and PQC support.", None),
    (r"PyCryptodome|pycryptodome", "PyCryptodome", QuantumStatus.VULNERABLE, "Classical ciphers and hashes.", None),
    (r'"node"\s*:\s*"([^"]+)"|node\s*>=?\s*([\d.]+)', "Node.js", QuantumStatus.VULNERABLE,
     "WebCrypto / crypto module: RSA, ECDSA, Ed25519. No native PQC.", None),
]

DEP_FILES = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile",
    "package.json", "package-lock.json", "go.mod", "go.sum",
    "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml",
    "conanfile.txt", "CMakeLists.txt", "vcpkg.json",
}


def _version_at_least(found: str | None, minimum: str | None) -> bool | None:
    if not found or not minimum:
        return None
    def parts(v):
        return [int(x) for x in re.findall(r"\d+", v)[:3]]
    try:
        return parts(found) >= parts(minimum)
    except Exception:
        return None


def scan_dependencies(root: Path) -> list[Finding]:
    """Scan dependency manifests and emit capability findings."""
    findings = []
    seen = set()
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in DEP_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        for pattern, family, status, note, pqc_from in LIBRARY_MAP:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                ver = next((g for g in m.groups() if g), None)
                key = (family, rel)
                if key in seen:
                    continue
                seen.add(key)
                extra = ""
                if pqc_from and ver:
                    ok = _version_at_least(ver, pqc_from)
                    if ok is True:
                        extra = f" Version {ver} meets PQC threshold {pqc_from}."
                        status = QuantumStatus.PQC
                    elif ok is False:
                        extra = f" Version {ver} is below PQC threshold {pqc_from}."
                findings.append(Finding(
                    id=f"DEP-{family}-{path.name}",
                    evidence_path=rel,
                    evidence_line=1,
                    evidence_snippet=m.group(0)[:120],
                    family=family,
                    quantum_status=status,
                    role="dependency",
                    source_scanner="qci-deps",
                    confidence=0.8,
                    notes=note + extra + (f" purl=pkg:generic/{family.lower()}@{ver}" if ver else ""),
                    parameter_set=ver or "",
                    notes=note + extra + (f" purl=pkg:generic/{family}@{ver}" if ver else ""),
                    recommendation="Confirm the linked crypto library version supports your target algorithms.",
                ))
    return findings
