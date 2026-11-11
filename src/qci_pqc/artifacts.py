"""Scan compiled artifacts for cryptographic indicators.

A .class file is read from its constant pool. A JAR is a zip of
those. The finding names the class and the algorithm string.
"""

from __future__ import annotations

import re
import struct
import tarfile
import tempfile
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



NATIVE = (".so", ".dll", ".dylib")


def _native(name: str) -> Finding | None:
    low = name.lower()
    if low.endswith(".txt") or not (low.endswith(NATIVE) or ".so." in low or ".dll." in low):
        return None
    base = Path(name).name
    ver = ""
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", base)
    if m:
        ver = m.group(1)
    base_name = Path(name).name.lower()
    fam = "OpenSSL" if base_name.startswith(("libcrypto.so", "libssl.so", "libcrypto-", "libssl-")) else ("BouncyCastle" if base_name.startswith("bcprov") else "Native")
    return Finding(
        id=f"ART-LIB-{base}",
        evidence_path="",
        evidence_line=0,
        evidence_snippet=base,
        family=fam,
        quantum_status=QuantumStatus.VULNERABLE,
        role="library",
        source_scanner="qci-artifact",
        confidence=0.7,
        parameter_set=ver,
        notes=f"Native library {base}" + (f" {ver}" if ver else ""),
    )


def _manifest(text: str) -> str:
    m = re.search(r"Implementation-Version:\s*(\S+)", text)
    return m.group(1) if m else ""

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



def _methods(data: bytes, entries: dict[int, str], start: int, strings: dict[int, int] | None = None) -> dict[str, str]:
    """Map a Utf8 algorithm string to the method that loads it."""
    if start + 6 > len(data):
        return {}
    i = start
    i += 2 + 2 + 2  # access, this, super
    if i + 2 > len(data):
        return {}
    iface = struct.unpack_from(">H", data, i)[0]
    i += 2 + 2 * iface
    if i + 2 > len(data):
        return {}
    fields = struct.unpack_from(">H", data, i)[0]
    i += 2
    for _ in range(fields):
        if i + 8 > len(data):
            return {}
        i += 6
        ac = struct.unpack_from(">H", data, i)[0]
        i += 2
        for _ in range(ac):
            if i + 6 > len(data):
                return {}
            ln = struct.unpack_from(">I", data, i + 2)[0]
            i += 6 + ln
    if i + 2 > len(data):
        return {}
    methods = struct.unpack_from(">H", data, i)[0]
    i += 2
    found = {}
    for _ in range(methods):
        if i + 8 > len(data):
            break
        name = entries.get(struct.unpack_from(">H", data, i + 2)[0], "")
        i += 6
        ac = struct.unpack_from(">H", data, i)[0]
        i += 2
        for _ in range(ac):
            if i + 6 > len(data):
                break
            aname = entries.get(struct.unpack_from(">H", data, i)[0], "")
            ln = struct.unpack_from(">I", data, i + 2)[0]
            info = data[i + 6:i + 6 + ln]
            i += 6 + ln
            if aname != "Code" or len(info) < 8:
                continue
            code_len = struct.unpack_from(">I", info, 4)[0]
            code = info[8:8 + code_len]
            j = 0
            while j < len(code):
                op = code[j]
                def _s(idx):
                    if strings and idx in strings:
                        return entries.get(strings[idx], "")
                    return entries.get(idx, "")
                if op == 0x12 and j + 1 < len(code):  # ldc
                    s = _s(code[j + 1])
                    if s:
                        found.setdefault(s, name)
                    j += 2
                elif op == 0x13 and j + 2 < len(code):  # ldc_w
                    s = _s(struct.unpack_from(">H", code, j + 1)[0])
                    if s:
                        found.setdefault(s, name)
                    j += 3
                else:
                    j += 1
    return found

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
    methods = {}
    try:
        # Re-walk is done inside _methods from a fresh parse of entries.
        count = struct.unpack_from(">H", data, 8)[0]
        i = 10
        entries = {}
        stridx = {}
        n = 1
        while n < count and i < len(data):
            tag = data[i]
            i += 1
            if tag == 1 and i + 2 <= len(data):
                length = struct.unpack_from(">H", data, i)[0]
                i += 2
                entries[n] = data[i:i + length].decode("utf-8", errors="replace")
                i += length
            elif tag == 8 and i + 2 <= len(data):
                stridx[n] = struct.unpack_from(">H", data, i)[0]
                i += 2
            elif tag in _FIXED and i + _FIXED[tag] <= len(data):
                i += _FIXED[tag]
            else:
                break
            n += 2 if tag in _TWO_SLOT else 1
        methods = _methods(data, entries, i, stridx)
    except Exception:
        methods = {}
    text = "\n".join(strings)
    out = []
    base = f"{jar}!{klass}" if jar else klass or rel
    for pat, fam, status, role in STRINGS:
        m = re.search(pat, text)
        if not m:
            continue
        token = m.group(0)
        method = methods.get(token, "")
        where = f"{base}.{method}" if method else base
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
        low_name = path.name.lower()
        is_native = not low_name.endswith(".txt") and (low_name.endswith(NATIVE) or ".so." in low_name or ".dll." in low_name)
        if not path.is_file() or (path.suffix.lower() not in ARTIFACT_SUFFIXES and not is_native):
            continue
        rel = str(path.relative_to(root))
        try:
            if path.name.lower().endswith(NATIVE) or ".so." in path.name.lower() or ".dll." in path.name.lower():
                lib = _native(path.name)
                if lib:
                    lib.evidence_path = rel
                    lib.evidence_snippet = path.name
                    findings.append(lib)
                continue
            if path.suffix.lower() in {".jar", ".war", ".ear"} and zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as zf:
                    names = zf.namelist()
                    for name in names:
                        if name.endswith(".class"):
                            findings.extend(_findings(zf.read(name), rel, jar=path.name))
                        elif not name.lower().endswith(".txt") and (name.lower().endswith(NATIVE) or ".so." in name.lower() or ".dll." in name.lower()):
                            lib = _native(name)
                            if lib:
                                lib.evidence_path = rel
                                lib.evidence_snippet = f"{path.name}!{lib.evidence_snippet}"
                                findings.append(lib)
                    if "META-INF/MANIFEST.MF" in names:
                        ver = _manifest(zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore"))
                        if ver:
                            for f in findings:
                                if f.evidence_path == rel and not f.parameter_set:
                                    f.parameter_set = ver
                                if f.evidence_path == rel:
                                    f.notes = (f.notes + f" Manifest {ver}.").strip()
                continue
            findings.extend(_findings(path.read_bytes(), rel))
        except Exception:
            continue
    return findings

IMAGE_SUFFIXES = {".tar", ".tgz"}


def _scan_tree(root: Path, label: str) -> list[Finding]:
    """Certs, configs, and class files inside an extracted image."""
    from .certs import inspect_pem
    out = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = f"{label}:{path.relative_to(root)}"
        if path.suffix.lower() in {".pem", ".crt", ".cer"} or "BEGIN" in path.read_bytes()[:40].decode("latin-1", errors="ignore"):
            try:
                for f in inspect_pem(path, root):
                    f.evidence_path = rel
                    f.source_scanner = "qci-artifact"
                    f.notes = (f.notes or "") + f" From image {label}."
                    out.append(f)
            except Exception:
                pass
        if path.suffix.lower() in {".conf", ".cnf", ".cfg"} or path.name in {"sshd_config", "nginx.conf"}:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"KexAlgorithms|ssl_certificate|MinProtocol|CipherString", text):
                out.append(Finding(
                    id=f"ART-CFG-{path.name}",
                    evidence_path=rel,
                    evidence_line=1,
                    evidence_snippet=path.name,
                    family="TLS-Cert-Config",
                    quantum_status=QuantumStatus.VULNERABLE,
                    role="config",
                    source_scanner="qci-artifact",
                    confidence=0.7,
                    notes=f"Config inside image {label}.",
                ))
    out.extend(scan_artifacts(root))
    for f in out:
        if not str(f.evidence_path).startswith(label):
            f.evidence_path = f"{label}:{f.evidence_path}"
            f.source_scanner = "qci-artifact"
    return out


def scan_images(root: Path) -> list[Finding]:
    findings = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if not (name.endswith(".tar") or name.endswith(".tar.gz") or name.endswith(".tgz")):
            continue
        try:
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp)
                with tarfile.open(path) as tf:
                    tf.extractall(dest, filter="data")
                # Docker save: layers are nested tars.
                for layer in dest.rglob("*.tar"):
                    with tarfile.open(layer) as inner:
                        inner.extractall(dest / "layers", filter="data")
                findings.extend(_scan_tree(dest, path.name))
        except Exception:
            continue
    return findings
