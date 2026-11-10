"""Resolve algorithms that are not written at the call site.

Three layers, added across PRs:
1. Config files (JSON, properties)
2. Call arguments and maps
3. Wiring / factory / injection
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding, QuantumStatus

KNOWN = {
    "AES": (QuantumStatus.SAFE_SYMMETRIC, "encrypt"),
    "AES/ECB": (QuantumStatus.SAFE_SYMMETRIC, "encrypt"),
    "AES/CBC": (QuantumStatus.SAFE_SYMMETRIC, "encrypt"),
    "RSA": (QuantumStatus.VULNERABLE, "keygen"),
    "MD5": (QuantumStatus.WEAK, "hash"),
    "SHA-1": (QuantumStatus.WEAK, "hash"),
    "SHA1": (QuantumStatus.WEAK, "hash"),
    "SHA-256": (QuantumStatus.SAFE_SYMMETRIC, "hash"),
    "HMAC-SHA256": (QuantumStatus.SAFE_SYMMETRIC, "mac"),
    "HmacSHA256": (QuantumStatus.SAFE_SYMMETRIC, "mac"),
    "DESEDE": (QuantumStatus.WEAK, "encrypt"),
}

def _finding(path: Path, root: Path, line: int, family: str, status, role: str, snippet: str) -> Finding:
    return Finding(
        id="RESOLVE",
        evidence_path=str(path.relative_to(root)),
        evidence_line=line,
        evidence_snippet=snippet[:200],
        family=family,
        quantum_status=status,
        role=role,
        source_scanner="qci-resolve",
        confidence=0.8,
        parameter_set=family,
    )


def resolve_configs(root: Path) -> list[Finding]:
    out = []
    for path in root.rglob("*"):
        if not path.is_file() or any(p in {".git", "node_modules"} for p in path.parts):
            continue
        if path.suffix.lower() == ".json":
            out.extend(_json(path, root))
        elif path.suffix.lower() == ".properties":
            out.extend(_properties(path, root))
    return out


def _json(path: Path, root: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []
    found = []
    def walk(node):
        if isinstance(node, dict):
            algo = str(node.get("algorithm", ""))
            mode = str(node.get("mode", ""))
            if algo.upper() in KNOWN:
                fam = f"{algo}-{mode}" if mode else algo
                st, role = KNOWN[algo.upper()]
                found.append(_finding(path, root, 1, fam if mode else algo, st, role, f"{algo}/{mode}" if mode else algo))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(data)
    return found


def _properties(path: Path, root: Path) -> list[Finding]:
    found = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        if "=" not in line or line.strip().startswith("#"):
            continue
        key, val = line.split("=", 1)
        token = val.strip().upper()
        if "ALGORITHM" in key.upper() and token in KNOWN:
            st, role = KNOWN[token]
            found.append(_finding(path, root, i, val.strip(), st, role, line.strip()))
    return found

def resolve_calls_and_maps(root: Path) -> list[Finding]:
    """Literals passed into crypto calls, and algorithm maps."""
    out = []
    call = re.compile(r"""(?:getInstance|digest|hashlib\.new)\s*\(\s*['"]([A-Za-z0-9/\-]+)['"]""")
    sysprop = re.compile(r"""getProperty\s*\(\s*['"][^'"]+['"]\s*,\s*['"]([^'"]+)['"]""")
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".py", ".java", ".kt"}:
            continue
        if any(part in {".git", "node_modules"} for part in path.parts):
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, line in enumerate(lines, 1):
            for m in call.finditer(line):
                token = m.group(1)
                base = token.split("/")[0].upper()
                if token.upper() in KNOWN or base in KNOWN:
                    st, role = KNOWN.get(token.upper(), KNOWN.get(base))
                    out.append(_finding(path, root, i, token, st, role, line.strip()))
            for m in sysprop.finditer(line):
                token = m.group(1).split("/")[0]
                if token.upper() in KNOWN:
                    st, role = KNOWN[token.upper()]
                    out.append(_finding(path, root, i, token, st, role, line.strip()))
            for name in ("HmacSHA256", "HmacSHA384", "HmacSHA512"):
                if name in line:
                    st, role = KNOWN["HmacSHA256"]
                    out.append(_finding(path, root, i, name, st, role, line.strip()))
    return out
