"""Scanner adapters. Internal pattern scanner + external tools."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Protocol

from .models import Finding, QuantumStatus
from .scanner import scan_path as internal_scan


class ScannerAdapter(Protocol):
    name: str

    def available(self) -> bool: ...
    def scan(self, root: Path) -> list[Finding]: ...


class InternalAdapter:
    name = "qci-pattern"

    def available(self) -> bool:
        return True

    def scan(self, root: Path) -> list[Finding]:
        return list(internal_scan(root))


class CryptoScanAdapter:
    """Adapter for csnp/cryptoscan (https://github.com/csnp/cryptoscan)."""

    name = "cryptoscan"

    def __init__(self, binary: str | None = None):
        self.binary = binary or shutil.which("cryptoscan") or "/tmp/cryptoscan"

    def available(self) -> bool:
        return Path(self.binary).is_file() and Path(self.binary).stat().st_mode & 0o111

    def scan(self, root: Path) -> list[Finding]:
        if not self.available():
            raise RuntimeError(f"cryptoscan binary not found at {self.binary}")

        result = subprocess.run(
            [self.binary, "scan", str(root), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode not in (0, 1):  # 1 often means findings exist
            raise RuntimeError(f"cryptoscan failed: {result.stderr[:500]}")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            # Some versions print progress before JSON; try to extract
            text = result.stdout
            start = text.find("{")
            if start == -1:
                return []
            data = json.loads(text[start:])

        findings = []
        raw_findings = data.get("findings") or data.get("results") or []
        for i, item in enumerate(raw_findings, 1):
            family = item.get("algorithm") or item.get("name") or item.get("pattern") or "unknown"
            location = item.get("file") or item.get("path") or item.get("location") or ""
            line = item.get("line") or item.get("lineNumber")
            snippet = (item.get("snippet") or item.get("match") or item.get("context") or "")[:200]
            risk = (item.get("quantumRisk") or item.get("risk") or item.get("severity") or "").lower()

            if "vulnerab" in risk or "critical" in risk:
                status = QuantumStatus.VULNERABLE
            elif "weak" in risk or "md5" in family.lower() or "sha-1" in family.lower() or "sha1" in family.lower():
                status = QuantumStatus.WEAK
            elif "pqc" in risk or "safe" in risk or "ml-" in family.lower() or "kyber" in family.lower():
                status = QuantumStatus.PQC
            elif "hybrid" in risk:
                status = QuantumStatus.HYBRID
            else:
                status = QuantumStatus.UNKNOWN

            findings.append(Finding(
                id=f"CS-{i:04d}",
                evidence_path=str(location),
                evidence_line=line,
                evidence_snippet=snippet,
                family=family,
                quantum_status=status,
                classical_weak=status == QuantumStatus.WEAK,
                source_scanner="cryptoscan",
                confidence=0.85,
            ))
        return findings


class QScanAdapter:
    """Adapter for @quantakrypto/qscan (https://github.com/quantakrypto/pqc-tools).
    Runs via npx (Node >= 20 required).
    """

    name = "qscan"

    def available(self) -> bool:
        return shutil.which("npx") is not None and shutil.which("node") is not None

    def scan(self, root: Path) -> list[Finding]:
        if not self.available():
            raise RuntimeError("npx/node not available for qscan adapter")

        result = subprocess.run(
            ["npx", "--yes", "@quantakrypto/qscan", str(root), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        # qscan may exit 1 when findings exist
        if result.returncode not in (0, 1):
            raise RuntimeError(f"qscan failed: {result.stderr[:500]}")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            text = result.stdout
            start = text.find("{")
            if start == -1:
                return []
            data = json.loads(text[start:])

        findings = []
        # qscan JSON shape: typically { findings: [...], inventory: {...}, ... }
        raw = data.get("findings") or data.get("results") or []
        for i, item in enumerate(raw, 1):
            family = (
                item.get("algorithm")
                or item.get("family")
                or item.get("ruleId")
                or item.get("name")
                or "unknown"
            )
            loc = item.get("file") or item.get("path") or item.get("location") or ""
            line = item.get("line") or item.get("startLine") or item.get("lineNumber")
            snippet = (item.get("snippet") or item.get("match") or item.get("text") or "")[:200]
            risk = str(item.get("severity") or item.get("quantum") or item.get("status") or "").lower()

            if any(x in risk for x in ("critical", "high", "vulnerab", "quantum")):
                status = QuantumStatus.VULNERABLE
            elif any(x in family.lower() for x in ("md5", "sha1", "sha-1", "des", "rc4")):
                status = QuantumStatus.WEAK
            elif any(x in family.lower() for x in ("ml-kem", "ml-dsa", "slh-dsa", "kyber", "dilithium", "pqc")):
                status = QuantumStatus.PQC
            else:
                status = QuantumStatus.UNKNOWN

            findings.append(Finding(
                id=f"QS-{i:04d}",
                evidence_path=str(loc),
                evidence_line=line,
                evidence_snippet=snippet,
                family=str(family),
                quantum_status=status,
                classical_weak=status == QuantumStatus.WEAK,
                source_scanner="qscan",
                confidence=0.8,
            ))
        return findings


class SemgrepAdapter:
    """Adapter for Semgrep with focused QCI crypto rules.
    Higher precision than pure regex because it uses AST matching where possible.
    """

    name = "semgrep"

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, root: Path) -> list[Finding]:
        if not self.available():
            raise RuntimeError("semgrep not found on PATH")

        rules_path = Path(__file__).parent / "rules" / "crypto.yml"
        if not rules_path.exists():
            raise RuntimeError(f"Rules file missing: {rules_path}")

        result = subprocess.run(
            [
                "semgrep",
                "--config", str(rules_path),
                "--json",
                "--quiet",
                str(root),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode not in (0, 1):
            raise RuntimeError(f"semgrep failed: {result.stderr[:500]}")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings = []
        for i, item in enumerate(data.get("results", []), 1):
            extra = item.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            family = meta.get("family") or extra.get("message", "unknown").split()[0]
            status_str = (meta.get("quantum_status") or "unknown").lower()
            status = {
                "vulnerable": QuantumStatus.VULNERABLE,
                "weak": QuantumStatus.WEAK,
                "pqc": QuantumStatus.PQC,
                "hybrid": QuantumStatus.HYBRID,
                "safe_symmetric": QuantumStatus.SAFE_SYMMETRIC,
            }.get(status_str, QuantumStatus.UNKNOWN)

            findings.append(Finding(
                id=f"SG-{i:04d}",
                evidence_path=item.get("path", ""),
                evidence_line=item.get("start", {}).get("line"),
                evidence_snippet=(extra.get("lines") or "")[:200],
                family=family,
                quantum_status=status,
                classical_weak=bool(meta.get("classical_weak", False)) or status == QuantumStatus.WEAK,
                role=meta.get("role"),
                source_scanner="semgrep",
                confidence=0.9,  # higher because AST-based
                notes=extra.get("message", ""),
            ))
        return findings


ADAPTERS: dict[str, type] = {
    "internal": InternalAdapter,
    "qci-pattern": InternalAdapter,
    "cryptoscan": CryptoScanAdapter,
    "qscan": QScanAdapter,
    "semgrep": SemgrepAdapter,
}


def get_adapter(name: str) -> ScannerAdapter:
    cls = ADAPTERS.get(name)
    if not cls:
        raise ValueError(f"Unknown adapter: {name}. Available: {list(ADAPTERS)}")
    return cls()
