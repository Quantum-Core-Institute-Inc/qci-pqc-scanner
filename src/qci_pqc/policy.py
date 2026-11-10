"""Policy-as-code evaluation and accepted-risk tracking."""

import json
from pathlib import Path

from .models import Finding, QuantumStatus


def load_policy(path: Path | None) -> dict:
    if not path or not path.exists():
        return {}
    return json.loads(path.read_text())


def load_accepted_risks(path: Path | None) -> dict:
    """Map of finding key -> justification."""
    if not path or not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {item["key"]: item for item in data.get("accepted", [])}


def finding_key(f: Finding) -> str:
    return f"{f.family}|{Path(f.evidence_path).name}|{f.evidence_line or 0}"


def evaluate_policy(findings: list[Finding], policy: dict, accepted: dict) -> dict:
    """Apply policy. Returns violations and waived findings."""
    violations = []
    waived = []

    fail_on = policy.get("fail_on", [])  # e.g. ["vulnerable"]
    require_acceptance = policy.get("require_acceptance_for", [])  # e.g. ["vulnerable"]

    for f in findings:
        key = finding_key(f)
        status = f.quantum_status.value

        if key in accepted:
            waived.append({"key": key, "family": f.family, "justification": accepted[key].get("justification", "")})
            continue

        if status in fail_on or status in require_acceptance:
            violations.append({
                "key": key,
                "family": f.family,
                "status": status,
                "path": f.evidence_path,
                "line": f.evidence_line,
                "reason": f"Status '{status}' requires acceptance or is a policy failure",
            })

    return {
        "violations": violations,
        "waived": waived,
        "passed": len(violations) == 0,
    }
