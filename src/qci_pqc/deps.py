"""Map known dependencies to libraries, with version and purl.

Direct manifests and lockfiles. A library is not an algorithm.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, QuantumStatus

# pattern, canonical name, purl type, min pqc version or None
LIBS = [
    (r"cryptography\s*[=<>~!]*\s*([\d.]+)?", "cryptography", "pypi", "48.0"),
    (r"pycryptodome\s*[=<>~!]*\s*([\d.]+)?", "pycryptodome", "pypi", None),
    (r"pyopenssl\s*[=<>~!]*\s*([\d.]+)?", "pyopenssl", "pypi", None),
    (r"pyjwt\s*[=<>~!]*\s*([\d.]+)?", "pyjwt", "pypi", None),
    (r"paramiko\s*[=<>~!]*\s*([\d.]+)?", "paramiko", "pypi", None),
    (r"bcrypt\s*[=<>~!]*\s*([\d.]+)?", "bcrypt", "pypi", None),
    (r"liboqs(?:-python)?\s*[=<>~!]*\s*([\d.]+)?", "liboqs", "pypi", None),
    (r"org\.bouncycastle:bc\w*-jdk\d+on:([\d.]+)", "bouncycastle", "maven", "1.79"),
    (r"<artifactId>bc\w*-jdk\d+on</artifactId>\s*<version>([\d.]+)", "bouncycastle", "maven", "1.79"),
    (r"nimbus-jose-jwt</artifactId>\s*<version>([\d.]+)|nimbus-jose-jwt:([\d.]+)", "nimbus-jose-jwt", "maven", None),
    (r"jjwt-(?:api|impl)[^<]*</artifactId>\s*<version>([\d.]+)|jjwt:([\d.]+)", "jjwt", "maven", None),
    (r'"jsonwebtoken"\s*:\s*"[\^~]?([\d.]+)"', "jsonwebtoken", "npm", None),
    (r'"crypto-js"\s*:\s*"[\^~]?([\d.]+)"', "crypto-js", "npm", None),
    (r'"node-forge"\s*:\s*"[\^~]?([\d.]+)"', "node-forge", "npm", None),
    (r'"bcryptjs"\s*:\s*"[\^~]?([\d.]+)"', "bcryptjs", "npm", None),
    (r'"@noble/post-quantum"\s*:\s*"[\^~]?([\d.]+)"', "@noble/post-quantum", "npm", None),
    (r'"@noble/curves"\s*:\s*"[\^~]?([\d.]+)"', "@noble/curves", "npm", None),
    (r'"@noble/hashes"\s*:\s*"[\^~]?([\d.]+)"', "@noble/hashes", "npm", None),
    (r'"jws"\s*:\s*"[\^~]?([\d.]+)"', "jws", "npm", None),
    (r'"jwa"\s*:\s*"[\^~]?([\d.]+)"', "jwa", "npm", None),
    (r"github\.com/cloudflare/circl\s+v?([\d.]+)", "circl", "golang", None),
    (r"golang\.org/x/crypto\s+v?([\d.]+)", "golang.org/x/crypto", "golang", None),
    (r"github\.com/golang-jwt/jwt/v\d+\s+v?([\d.]+)", "github.com/golang-jwt/jwt", "golang", None),
    (r"openssl/([\d.]+[a-z]?)|find_package\(OpenSSL\s+([\d.]+)", "openssl", "conan", "3.5"),
    (r"libsodium/([\d.]+)|find_package\(libsodium", "libsodium", "conan", None),
]

DEP_FILES = {
    "requirements.txt", "pyproject.toml", "package.json", "package-lock.json",
    "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "conanfile.txt",
    "CMakeLists.txt",
}


def _ver(m) -> str:
    return next((g for g in m.groups() if g), "") or ""


def scan_dependencies(root: Path) -> list[Finding]:
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
        for pat, name, eco, _pqc in LIBS:
            for m in re.finditer(pat, text, re.I):
                ver = _ver(m)
                key = (name, rel)
                if key in seen:
                    continue
                seen.add(key)
                purl = f"pkg:{eco}/{name}" + (f"@{ver}" if ver else "")
                findings.append(Finding(
                    id=f"DEP-{name}-{path.name}",
                    evidence_path=rel,
                    evidence_line=1,
                    evidence_snippet=m.group(0)[:120],
                    family=name,
                    quantum_status=QuantumStatus.VULNERABLE,
                    role="library",
                    source_scanner="qci-deps",
                    confidence=0.9,
                    parameter_set=ver,
                    notes=purl,
                ))
    return findings
