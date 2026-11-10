from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class QuantumStatus(str, Enum):
    VULNERABLE = "vulnerable"      # Shor-vulnerable (RSA, ECDSA, etc.)
    PQC = "pqc"                    # Post-quantum (ML-KEM, ML-DSA, etc.)
    HYBRID = "hybrid"
    SAFE_SYMMETRIC = "safe_symmetric"  # AES-256, SHA-256, etc.
    WEAK = "weak"                  # MD5, SHA-1, DES, small keys
    UNKNOWN = "unknown"


@dataclass
class Finding:
    id: str
    evidence_path: str
    evidence_line: Optional[int]
    evidence_snippet: str
    family: str
    parameter_set: Optional[str] = None
    role: Optional[str] = None
    quantum_status: QuantumStatus = QuantumStatus.UNKNOWN
    classical_weak: bool = False
    defect_cwe: Optional[str] = None
    source_scanner: str = "qci-internal"
    confidence: float = 0.5
    notes: str = ""
    # New actionable fields
    priority_score: int = 0
    priority_reasons: list[str] = field(default_factory=list)
    compliance_note: str = ""
    migration_phase: str = ""
    timeline_flags: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class CoverageScore:
    recognised: int = 0
    total: int = 0
    false_alarms: int = 0

    @property
    def recall(self) -> float:
        return self.recognised / self.total if self.total else 0.0


@dataclass
class Inventory:
    project: str
    scanners_used: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, CoverageScore] = field(default_factory=dict)
    readiness_score: float = 0.0
    readiness_breakdown: dict = field(default_factory=dict)
    priority_findings: list[Finding] = field(default_factory=list)
    calibration: dict = field(default_factory=dict)
    reproducible: bool = False
