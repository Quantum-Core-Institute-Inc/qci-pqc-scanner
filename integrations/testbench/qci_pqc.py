"""Adapter for the QCI PQC Readiness Scanner (qci-pqc-scan), built against version 0.3.0.

The scanner writes a schema-valid CycloneDX 1.6 CBOM (cbom.json). Its component names fall into
two kinds, and this adapter treats them differently on purpose:

  Exact algorithm names ("RSA", "ML-KEM-768", "AES-GCM") are translated to the testbench's names
  and scored strictly, like any other scanner's output.

  Risk-signal categories ("DH/ECDH", "SSH-Weak-Cipher", "Hybrid-KEM", "TLS-Classical-Cipher") don't
  say which algorithm they found, so they can't be credited as one without guessing. They are kept
  out of the strict score (renamed to an opaque "qci-category-N" with the original kept in a
  "qci:category" property, because "DH/ECDH" and "RSA/ECDSA" otherwise read as EC) and scored separately as *signal coverage*: does a category signal sit on the line of
  a ground-truth finding it plausibly describes?

Nothing is added to what the scanner reported. Names the tables don't know are reported as
unmapped, so a new scanner version with new families shows up instead of silently scoring zero.
"""
from __future__ import annotations

import copy
from pathlib import Path

from cbomlib import FAMILIES, same_file

ADAPTER_VERSION = "1.0"
BUILT_FOR = "qci-pqc-scan 0.3.0"

# QCI family name -> testbench algorithm name (scored strictly).
EXACT = {
    "RSA": "RSA", "ECDSA": "ECDSA", "ECDH": "ECDH", "Ed25519": "Ed25519", "X25519": "X25519",
    "SHA-1": "SHA-1", "MD5": "MD5", "SHA-256": "SHA-256", "SHA-384": "SHA-384", "SHA-512": "SHA-512",
    "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
    "HmacSHA256": "HMAC-SHA-256", "HmacSHA384": "HMAC-SHA-384", "HmacSHA512": "HMAC-SHA-512",
    "AES": "AES", "AES-ECB": "AES-ECB", "AES-GCM": "AES-GCM", "ChaCha20-Poly1305": "ChaCha20-Poly1305",
    "DES": "DES", "3DES": "3DES",
    "ML-KEM": "ML-KEM", "ML-KEM-512": "ML-KEM-512", "ML-KEM-768": "ML-KEM-768", "ML-KEM-1024": "ML-KEM-1024",
    "ML-DSA": "ML-DSA", "ML-DSA-44": "ML-DSA-44", "ML-DSA-65": "ML-DSA-65", "ML-DSA-87": "ML-DSA-87",
    "SLH-DSA": "SLH-DSA", "FN-DSA": "FN-DSA", "Kyber-prestandard": "Kyber",
    "SSH-Ed25519-HostKey": "Ed25519",
    "X25519MLKEM768": "X25519MLKEM768",
    "ECC-P-256": "ECC-P-256",
    "ECC-P-384": "ECC-P-384",
    "SecP384r1MLKEM1024": "SecP384r1MLKEM1024",
    "sntrup761x25519": "sntrup761x25519",
    "TLS-1.3": "TLS-1.3",
    "DH": "DH", "DSA": "DSA", "HMAC": "HMAC", "PBKDF2": "PBKDF2", "SHA-3": "SHA-3",
    "HMAC-SHA-256": "HMAC-SHA-256", "HMAC-SHA-1": "HMAC-SHA-1", "HMAC-SHA-512": "HMAC-SHA-512",
    "PBKDF2-SHA-256": "PBKDF2-SHA-256", "PBKDF2-SHA-1": "PBKDF2-SHA-1",
}


def _fams(*names):
    return lambda fam, _f, _m: fam in names


def _flag(flag):
    return lambda fam, _f, _m: bool(FAMILIES.get(fam, {}).get(flag))


def _suite_with(*parts, require_kx=False):
    def pred(fam, _f, _m):
        if not FAMILIES.get(fam, {}).get("suite"):
            return False
        if require_kx and not ("_WITH_" in fam and ("ECDHE" in fam or "DHE" in fam)):
            return False
        return any(p in fam for p in parts)
    return pred


def _key_material(fam, f, mat_idx):
    return mat_idx.get(f["id"], (None, None))[1] == "key"


# QCI risk category -> which ground-truth findings it plausibly describes (signal coverage only).
SIGNALS = {
    "DH/ECDH": _fams("DH", "X25519", "EC"),
    "SSH-Classical-Kex": _fams("X25519", "EC", "DH"),
    "SSH-Weak-Kex": _fams("DH"),
    "SSH-Legacy-Kex": _fams("DH"),
    "RSA/ECDSA": _fams("RSA", "EC", "DSA"),
    "SSH-Classical-HostKey": _fams("RSA", "EC", "DSA"),
    "TLS1.0/1.1": _fams("TLS-1.0", "TLS-1.1"),
    "TLS-Weak-Protocol": _fams("TLS-1.0", "TLS-1.1"),
    "OpenSSL-Config": _fams("TLS-1.0", "TLS-1.1"),
    "TLS-Weak-Cipher": _suite_with("3DES", "RC4", "_DES_", "NULL", "EXPORT", "MD5"),
    "TLS-Classical-Cipher": _suite_with("AES", require_kx=True),
    "SSH-Weak-Cipher": _fams("AES", "3DES", "RC4", "DES"),
    "SSH-Modern-Cipher": _fams("ChaCha20-Poly1305", "AES"),
    "SSH-Weak-MAC": _fams("HMAC"),
    "SSH-PQC-Kex": _flag("hybrid"),
    "Hybrid-KEM": _flag("hybrid"),
    "Hybrid-Named": _flag("hybrid"),
    "Hybrid-PQC": _flag("hybrid"),
    "Hybrid-Sign": _flag("hybrid"),
    "Java-PQC": _flag("pq"),
    "liboqs-PQC": _flag("pq"),
    "Go-CIRCL-PQC": _flag("pq"),
    "PQC-Dependency": _flag("pq"),
    "X509-Cert": _key_material,
    "PKCS8": _key_material,
    "Private-Key": _key_material,
    "TLS-Cert-Config": lambda *_: False,   # points at a certificate file; describes no algorithm itself
    "Java-TLS-Policy": lambda *_: False,
}

# Pointers to configuration, not claims about an algorithm: never counted as signal false alarms.
INFORMATIONAL = {"TLS-Cert-Config", "Java-TLS-Policy"}

# Algorithms the scanner reports that the testbench doesn't model: neither scored nor penalized.
NOT_MODELED = {"BLAKE2", "HQC", "Classic-McEliece", "BIKE", "Python-cryptography", "pyOpenSSL", "liboqs",
               "Go-CIRCL", "BouncyCastle", "OpenSSL", "Node.js"}


def translate(qci_bom: dict) -> tuple[dict, list[dict], list[str]]:
    """-> (bom for the scorer, risk-signal records, unmapped QCI names)."""
    bom = copy.deepcopy(qci_bom)
    signals, unmapped, opaque = [], set(), 0
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        name = c.get("name", "")
        if name in EXACT:
            c["name"] = EXACT[name]
            continue
        if name in SIGNALS:
            for o in (c.get("evidence") or {}).get("occurrences", []):
                signals.append({"category": name, "location": o.get("location", ""), "line": o.get("line"),
                                "ref": c.get("bom-ref")})
        elif name not in NOT_MODELED:
            unmapped.add(name)
        # Opaque name: "qci:DH/ECDH" would still be read as EC by any substring normalizer. The original
        # category is kept as a property, and parameterSetIdentifier (QCI copies the name there) is dropped.
        opaque += 1
        c["name"] = f"qci-category-{opaque}"
        ap = (c.get("cryptoProperties") or {}).get("algorithmProperties")
        if isinstance(ap, dict):
            ap.pop("parameterSetIdentifier", None)
        c.setdefault("properties", []).append({"name": "qci:category", "value": name})
    md = bom.setdefault("metadata", {}).setdefault("properties", [])
    md.append({"name": "cbom-testbench:adapter", "value": f"qci_pqc {ADAPTER_VERSION} (built for {BUILT_FOR})"})
    return bom, signals, sorted(unmapped)


def _near(sig_line, lines, tol=1):
    if not lines or not isinstance(sig_line, int):
        return True  # file-level asset, or a signal without a line
    return any(abs(sig_line - ln) <= tol for ln in lines)


def signal_coverage(report: dict, gt: dict, signals: list[dict], mat_idx: dict) -> dict:
    """Credit risk-signal categories with ground-truth findings they describe, on the same line (±1).

    report: the strict scorer result (already scope-filtered); gt: ground truth with resolved lines."""
    by_id = {f["id"]: f for f in gt["findings"]}
    covered, by_category, used = {}, {}, set()
    for r in report["results"]:
        f = by_id[r["id"]]
        places = [(f["file"], f.get("lines", []))] + [(a["file"], a.get("lines", [])) for a in f.get("alt_files", [])]
        for i, s in enumerate(signals):
            pred = SIGNALS[s["category"]]
            if not any(same_file(s["location"], p) and _near(s["line"], lines) for p, lines in places):
                continue
            if pred(f["family"], f, mat_idx):
                covered.setdefault(r["id"], []).append(s["category"])
                by_category.setdefault(s["category"], set()).add(r["id"])
                used.add(i)
    results = report["results"]
    strict = {r["id"] for r in results if r["detected"]}
    signal_only = [rid for rid in covered if rid not in strict]
    unused = [s for i, s in enumerate(signals) if i not in used and s["category"] not in INFORMATIONAL]
    n = len(results)
    return {
        "expected": n,
        "strict_detected": len(strict),
        "signal_only": len(signal_only),
        "combined": len(strict | set(covered)),
        "strict_recall": round(100 * len(strict) / n, 1) if n else None,
        "combined_recall": round(100 * len(strict | set(covered)) / n, 1) if n else None,
        "signal_only_ids": sorted(signal_only),
        "by_category": {k: len(v) for k, v in sorted(by_category.items())},
        "signals_total": len(signals),
        "signals_matching_nothing": unused,
    }


def signals_markdown(sc: dict, unmapped: list[str]) -> str:
    out = ["## Risk-signal coverage (QCI categories)", "",
           "QCI reports many findings as risk categories (`DH/ECDH`, `SSH-Weak-Cipher`, `Hybrid-KEM`) rather "
           "than specific algorithms. Those aren't credited in the strict score above. Here they are credited "
           "when a category sits on the line (±1) of an expected finding it plausibly describes.", "",
           f"- Strict detections: **{sc['strict_detected']}/{sc['expected']}** ({sc['strict_recall']}%)",
           f"- Additional findings covered only by a category signal: **{sc['signal_only']}**",
           f"- Combined coverage: **{sc['combined']}/{sc['expected']}** ({sc['combined_recall']}%)",
           f"- Category signals emitted: {sc['signals_total']}; matching no expected finding: "
           f"{len(sc['signals_matching_nothing'])}", ""]
    if sc["by_category"]:
        out += ["| Category | Expected findings it covers |", "|---|---|"]
        out += [f"| `{k}` | {v} |" for k, v in sc["by_category"].items()]
        out.append("")
    if sc["signals_matching_nothing"]:
        out += ["Category signals that describe nothing in the ground truth (signal-level false alarms):", ""]
        for s in sc["signals_matching_nothing"][:30]:
            out.append(f"- `{s['category']}` at `{s['location']}`:{s['line']}")
        out.append("")
    if unmapped:
        out += ["**Unmapped QCI names** (new in this scanner version? add them to the adapter's tables): "
                + ", ".join(f"`{u}`" for u in unmapped), ""]
    return "\n".join(out) + "\n"
