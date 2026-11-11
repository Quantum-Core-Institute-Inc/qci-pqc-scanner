"""Accuracy calibration against the labeled golden corpus."""

from pathlib import Path
from .models import Finding, QuantumStatus
from .scanner import scan_path


def calibrate(corpus_dir: Path) -> dict:
    """Run scanner on corpus and compute simple precision/recall against expected labels.

    Expected labels are inferred from filename conventions and content for the MVP corpus.
    """
    findings = list(scan_path(corpus_dir))

    # Ground truth approximations from known files
    expected_positive = {
        ("rsa", "sample.py"), ("ecdsa", "sample.py"), ("md5", "sample.py"),
        ("sha1", "sample.py"), ("ml-kem", "sample.py"),
        ("rsa", "CryptoExample.java"), ("md5", "CryptoExample.java"),
        ("rsa", "go_crypto.go"), ("md5", "node_crypto.js"),
        ("rsa", "key.pem"), ("ml-kem", "pqc_ref.py"),
        ("ml-kem", "pqc_algorithms.py"), ("ml-dsa", "pqc_algorithms.py"),
        ("slh-dsa", "pqc_algorithms.py"), ("ml-kem", "lib_examples.py"),
        ("rsa", "calib_positive.py"), ("ecdsa", "calib_positive.py"),
        ("md5", "calib_positive.py"), ("ml-kem", "calib_positive.py"),
        ("ml-kem", "realworld_libs.py"), ("ml-dsa", "realworld_libs.py"),
        ("rsa", "RealWorldJava.java"), ("ml-kem", "RealWorldJava.java"),
        ("rsa", "calib_extra_positive.py"),
        ("md5", "calib_extra_positive.py"),
        ("ml-kem", "calib_extra_positive.py"),
        ("ml-dsa", "calib_extra_positive.py"),
        ("ecdsa", "calib_expand_positive.py"),
        ("sha1", "calib_expand_positive.py"),
        ("ml-dsa", "calib_expand_positive.py"),
        ("rsa", "realworld_go.go"),
        ("ml-kem", "realworld_go.go"),
    }

    detected = set()
    false_positives = []
    for f in findings:
        key = (f.family.lower().split("-")[0], Path(f.evidence_path).name)
        # Normalize family
        fam = f.family.lower()
        fname = Path(f.evidence_path).name
        norm = None
        if "rsa" in fam:
            norm = "rsa"
        elif "ecdsa" in fam or "ec" == fam:
            norm = "ecdsa"
        elif "md5" in fam:
            norm = "md5"
        elif "sha-1" in fam or "sha1" in fam:
            norm = "sha1"
        elif "ml-kem" in fam or "mlkem" in fam:
            norm = "ml-kem"
        elif "ml-dsa" in fam or "mldsa" in fam:
            norm = "ml-dsa"
        elif "slh" in fam:
            norm = "slh-dsa"
        if norm:
            detected.add((norm, fname))
            if (norm, fname) not in expected_positive and f.quantum_status in (
                QuantumStatus.VULNERABLE, QuantumStatus.WEAK
            ):
                # Potential FP if not in expected and not a known PQC file
                if "negative" in fname or "safe" in fname:
                    false_positives.append(f)

    true_positives = detected & expected_positive
    false_negatives = expected_positive - detected

    precision = len(true_positives) / len(detected) if detected else 0.0
    recall = len(true_positives) / len(expected_positive) if expected_positive else 0.0

    def surface(name: str) -> str:
        ext = Path(name).suffix.lower()
        return {".py": "python", ".java": "java", ".go": "go", ".js": "javascript",
                ".pem": "cert", ".crt": "cert", ".class": "artifact", ".jar": "artifact"}.get(ext, "other")

    by_surface = {}
    for fam, name in expected_positive:
        s = surface(name)
        slot = by_surface.setdefault(s, {"expected": 0, "found": 0})
        slot["expected"] += 1
        if (fam, name) in detected:
            slot["found"] += 1
    for s, slot in by_surface.items():
        slot["recall"] = round(slot["found"] / slot["expected"], 3) if slot["expected"] else 0.0

    return {
        "true_positives": len(true_positives),
        "false_positives": len(false_positives),
        "false_negatives": len(false_negatives),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "total_findings": len(findings),
        "expected_positive": len(expected_positive),
        "by_surface": by_surface,
        "corpus": "bundled",
        "independent": False,
    }
