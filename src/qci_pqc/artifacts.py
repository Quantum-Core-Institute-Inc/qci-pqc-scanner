"""Scan compiled artifacts for cryptographic indicators.

A .class file is read from its constant pool. A JAR is a zip of
those. The finding names the class and the algorithm string.
"""

from __future__ import annotations

import re
import struct
import zipfile
from pathlib import Path

from .models import Finding, QuantumStatus

ARTIFACT_SUFFIXES = {".jar", ".class", ".war", ".ear"}

# tag -> (size after the tag, or None for variable)
_FIXED = {
    3: 4, 4: 4,          # Integer, Float
    5: 8, 6: 8,          # Long, Double (two slots)
    7: 2, 8: 2,          # Class, String
    9: 4, 10: 4, 11: 4,  # Fieldref, Methodref, InterfaceMethodref
    12: 4,               # NameAndType
    15: 3,               # MethodHandle
    16: 2,               # MethodType
    17: 4, 18: 4,        # Dynamic, InvokeDynamic
    19: 2, 20: 2,        # Module, Package
}
_TWO_SLOT = {5, 6}

STRINGS = [
    (r"AES/GCM|AES/CBC|AES/ECB", "AES", QuantumStatus.SAFE_SYMMETRIC, "cipher"),
    (r"RSA/ECB|SHA256withRSA|SHA1withRSA", "RSA", QuantumStatus.VULNERABLE, "sign"),
    (r"ML-KEM|ML-DSA", "ML-KEM", QuantumStatus.PQC, "kem"),
    (r"HmacSHA256|HmacSHA512", "HMAC", QuantumStatus.SAFE_SYMMETRIC, "mac"),
    (r"DES/CBC|DESede", "DES", QuantumStatus.WEAK, "cipher"),
]


def _pool(data: bytes) -> tuple[list[str], str]:
    """Return Utf8 strings and the this_class name. Empty on a bad file."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return [], ""
    count = struct.unpack_from(">H", data, 8)[0]
    i = 10
    entries: dict[int, str] = {}
    classes: dict[int, int] = {}
    n = 1
    while n < count and i < len(data):
        tag = data[i]
        i += 1
        if tag == 1:
            if i + 2 > len(data):
                break
            length = struct.unpack_from(">H", data, i)[0]
            i += 2
            entries[n] = data[i:i + length].decode("utf-8", errors="replace")
            i += length
        elif tag == 7 and i + 2 <= len(data):
            classes[n] = struct.unpack_from(">H", data, i)[0]
            i += 2
        elif tag in _FIXED and i + _FIXED[tag] <= len(data):
            i += _FIXED[tag]
        else:
            break
        n += 2 if tag in _TWO_SLOT else 1
    this = ""
    if i + 4 <= len(data):
        this_index = struct.unpack_from(">H", data, i + 2)[0]
        this = entries.get(classes.get(this_index, 0), "")
    return list(entries.values()), this.replace("/", ".")


def _param(token: str, family: str) -> str:
    """Same reading as source: mode, hash, or the string itself."""
    if family == "AES":
        mode = "GCM" if "GCM" in token else ("CBC" if "CBC" in token else ("ECB" if "ECB" in token else ""))
        bits = "256" if "256" in token else ("128" if "128" in token else "")
        return "-".join(x for x in (bits, mode) if x)
    if family == "RSA" and "with" in token.lower():
        hash_ = token.lower().split("with")[0].replace("sha", "SHA-")
        return hash_ if hash_.startswith("SHA") else ""
    if family == "HMAC":
        return "SHA-256" if "256" in token else ("SHA-512" if "512" in token else "")
    if family == "DES" and "CBC" in token:
        return "CBC"
    return ""


def _findings(data: bytes, rel: str, jar: str = "") -> list[Finding]:
    strings, klass = _pool(data)
    if not strings:
        return []
    text = "\n".join(strings)
    out = []
    where = f"{jar}!{klass}" if jar else klass or rel
    for pat, fam, status, role in STRINGS:
        m = re.search(pat, text)
        if not m:
            continue
        token = m.group(0)
        out.append(Finding(
            id=f"ART-{fam}-{klass or Path(rel).name}",
            evidence_path=rel,
            evidence_line=0,
            evidence_snippet=f"{where}: {token}",
            family=fam,
            quantum_status=status,
            role=role,
            source_scanner="qci-artifact",
            confidence=0.8,
            notes=f"Constant pool of {klass or rel}.",
            parameter_set=_param(token, fam),
        ))
    return out


def scan_artifacts(root: Path) -> list[Finding]:
    findings = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in ARTIFACT_SUFFIXES:
            continue
        rel = str(path.relative_to(root))
        try:
            if path.suffix.lower() in {".jar", ".war", ".ear"} and zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as zf:
                    for name in zf.namelist():
                        if name.endswith(".class"):
                            findings.extend(_findings(zf.read(name), rel, jar=path.name))
                continue
            findings.extend(_findings(path.read_bytes(), rel))
        except Exception:
            continue
    return findings
