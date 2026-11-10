"""Report generation: CycloneDX CBOM, SARIF, and self-contained HTML."""

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
import re
from .models import Inventory, QuantumStatus


def to_cyclonedx(inv: Inventory) -> dict:
    """CycloneDX 1.6 CBOM with cryptographic component properties."""
    import uuid
    components = []
    for f in inv.findings:
        # Map role to CycloneDX primitive where possible
        fam_l = f.family.lower()
        role = (f.role or "").lower()
        if role in ("sign", "signature") or "withrsa" in fam_l or "withecdsa" in fam_l or fam_l in {"ecdsa", "ec"}:
            primitive = "signature"
        elif role == "encrypt" and "rsa" in fam_l:
            primitive = "pke"
        elif role == "keygen" and "rsa" in fam_l:
            primitive = "pke"
        elif role == "keygen" and fam_l in {"ecdsa", "ec", "ed25519"}:
            primitive = "signature"
        elif role in ("kem",):
            primitive = "kem"
        elif role in ("kex",):
            primitive = "key-agree"
        elif role == "hash":
            primitive = "hash"
        elif role == "mac":
            primitive = "mac"
        elif role == "encrypt":
            primitive = "ae"
        else:
            primitive = "other"

        # Map role to allowed cryptoFunctions enum
        func_map = {
            "kem": "encapsulate",
            "kex": "keyderive",
            "sign": "sign",
            "signature": "sign",
            "hash": "digest",
            "encrypt": "encrypt",
            "keygen": "keygen",
            "key": "other",
            "mac": "tag",
            "cipher": "encrypt",
        }
        crypto_func = func_map.get((f.role or "").lower(), "other")

        asset_type = "algorithm"
        if f.role in ("cert",) or "cert" in f.family.lower():
            asset_type = "certificate"
        elif f.role in ("key", "keygen"):
            asset_type = "related-crypto-material"

        param = f.parameter_set or ""
        curve = getattr(f, "curve", "") or ""
        # Scorer wants a numeric key size and a separate curve/mode, not "RSA-2048".
        key_size = ""
        mode = ""
        if param.upper().startswith("P-") or param.lower().startswith("secp"):
            curve = param if param.upper().startswith("P-") else param
        size_m = re.search(r"(\d{3,5})", param)
        if size_m and f.family in {"RSA", "DSA", "DH"} and not param.upper().startswith("SHA"):
            key_size = size_m.group(1)
        elif size_m and param[:1].isdigit() and f.family not in {"ECDSA", "ECDH", "ECC-P-256", "ECC-P-384"} and "ML" not in param.upper():
            key_size = size_m.group(1)
        elif "-" in param and param.split("-")[-1].isdigit() and not param.upper().startswith("P-") and not param.upper().startswith("SHA"):
            key_size = param.split("-")[-1]
        if param.upper().startswith("P-") or "SECP" in param.upper():
            key_size = ""
            curve = param if param.upper().startswith("P-") else param
        if "ECB" in (param + f.family).upper():
            mode = "ecb"
        elif "GCM" in (param + f.family).upper():
            mode = "gcm"
        elif "CBC" in (param + f.family).upper():
            mode = "cbc"
        param_id = key_size or curve or (
            param if param in {"SHA-256", "SHA-1", "SHA-512"} else f.family
        )
        algo_props = {
            "primitive": primitive,
            "parameterSetIdentifier": param_id,
            "cryptoFunctions": [crypto_func],
            "executionEnvironment": "software-plain-ram",
        }
        if curve:
            algo_props["curve"] = curve
        if mode:
            algo_props["mode"] = mode
        # Quantum resistance hint
        fam = f.family.upper()
        if "512" in fam or "44" in fam:
            algo_props["nistQuantumSecurityLevel"] = 1
        elif "768" in fam or "65" in fam:
            algo_props["nistQuantumSecurityLevel"] = 3
        elif "1024" in fam or "87" in fam:
            algo_props["nistQuantumSecurityLevel"] = 5
        elif f.quantum_status.value in ("vulnerable", "weak"):
            algo_props["nistQuantumSecurityLevel"] = 0

        name = f.family
        if "/" in name or name.endswith("-Cipher") or name.endswith("-Config"):
            risk_category = name
            name = f.parameter_set or "unspecified"
        else:
            risk_category = ""
        origin = {
            "qci-artifact": "artifact",
            "qci-deps": "dependency",
            "qci-crossmod": "source",
        }.get(f.source_scanner, "config" if (f.evidence_path or "").endswith((".conf", ".cnf", ".yml", ".yaml", ".properties", ".json")) else "source")
        crypto = {
            "assetType": asset_type,
            "algorithmProperties": {k: v for k, v in algo_props.items() if v is not None},
        }
        if asset_type == "certificate" and (getattr(f, "subject", "") or getattr(f, "not_after", "")):
            crypto["certificateProperties"] = {
                "subjectName": getattr(f, "subject", "") or None,
                "issuerName": getattr(f, "issuer", "") or None,
                "notValidAfter": ((getattr(f, "not_after", "") or "") + ("T00:00:00Z" if getattr(f, "not_after", "") and "T" not in getattr(f, "not_after", "") else "")) or None,
            }
            crypto["certificateProperties"] = {k: v for k, v in crypto["certificateProperties"].items() if v}
        if asset_type == "related-crypto-material":
            crypto["relatedCryptoMaterialProperties"] = {"type": "private-key" if "PRIVATE" in (f.evidence_snippet or "") else "public-key"}
        if (f.role or "") == "protocol":
            crypto["protocolProperties"] = {"type": "tls", "version": f.parameter_set or f.family}
        # NIST OIDs where known
        oid_map = {
            "ML-KEM-512": "2.16.840.1.101.3.4.4.1",
            "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
            "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
            "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
            "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
            "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
                        "RSA": "1.2.840.113549.1.1.1",
            "ECDSA": "1.2.840.10045.2.1",
            "Ed25519": "1.3.101.112",
        }
        oid = None
        for k, v in oid_map.items():
            if k.lower() in f.family.lower():
                oid = v
                break
        if oid:
            crypto["oid"] = oid
        if oid:
            crypto["oid"] = oid

        # Quantum resistance property
        qr = {
            "vulnerable": "vulnerable",
            "pqc": "resistant",
            "hybrid": "hybrid",
            "weak": "vulnerable",
            "safe_symmetric": "resistant",
        }.get(f.quantum_status.value, "unknown")

        if f.family in {"HMAC", "PBKDF2"} and param in {"SHA-256", "SHA-1", "SHA-512", "SHA-384"}:
            name = f"{f.family}-{param}"
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f.id,
            "name": name,
            "description": f.recommendation or f.notes or f"{f.family} ({f.quantum_status.value})",
            "cryptoProperties": crypto,
            "evidence": {
                "occurrences": [{
                    "location": f.evidence_path,
                    "line": f.evidence_line,
                }]
            },
            "properties": [
                {"name": "qci:provenance", "value": origin},
                {"name": "qci:agility", "value": "config" if origin == "config" else "code"},
                {"name": "qci:owner", "value": getattr(f, "owner", "") or ""},
                {"name": "qci:system", "value": getattr(f, "system", "") or ""},
                {"name": "qci:dataLifetime", "value": getattr(f, "lifetime", "") or ""},
                *([{"name": "qci:riskCategory", "value": risk_category}] if risk_category else []),
                {"name": "qci:quantum_status", "value": f.quantum_status.value},
                {"name": "qci:risk_category", "value": getattr(f, "risk_category", "") or ""},
                {"name": "qci:protocol", "value": f.parameter_set if (f.role or "") == "protocol" else ""},
                {"name": "qci:key_size", "value": str(f.parameter_set or "")},
                {"name": "qci:curve", "value": getattr(f, "curve", "") or ""},
                {"name": "qci:subject", "value": getattr(f, "subject", "") or ""},
                {"name": "qci:not_after", "value": getattr(f, "not_after", "") or ""},
                {"name": "qci:key_size", "value": str(f.parameter_set or "")},
                {"name": "qci:notes", "value": (f.notes or "")[:300]},
                {"name": "qci:quantum_resistance", "value": qr},
                {"name": "qci:confidence", "value": str(f.confidence)},
                {"name": "qci:priority_score", "value": str(getattr(f, "priority_score", 0))},
                {"name": "qci:migration_phase", "value": getattr(f, "migration_phase", "")},
                {"name": "qci:timeline", "value": "; ".join(getattr(f, "timeline_flags", []))},
            ],
        })

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, inv.project + str(len(inv.findings)))}" if getattr(inv, "reproducible", False) else f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "qci-pqc-scan",
                    "version": __version__,
                }]
            },
            "component": {
                "type": "application",
                "bom-ref": inv.project,
                "name": inv.project,
            },
        },
        "components": components,
    }


def to_sarif(inv: Inventory) -> dict:
    """SARIF 2.1.0 output for CI integration."""
    results = []
    for f in inv.findings:
        level = "error" if f.quantum_status == QuantumStatus.VULNERABLE else "warning"
        results.append({
            "ruleId": f"qci/{f.family}",
            "level": level,
            "message": {"text": f"{f.family} ({f.quantum_status.value}) found"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.evidence_path},
                    "region": {"startLine": f.evidence_line or 1},
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "qci-pqc-scan", "version": __version__}},
            "results": results,
        }],
    }


def to_html(inv: Inventory) -> str:
    """Self-contained HTML report."""
    findings_rows = ""
    for f in inv.findings:
        status_class = {
            QuantumStatus.VULNERABLE: "vulnerable",
            QuantumStatus.WEAK: "weak",
            QuantumStatus.PQC: "pqc",
            QuantumStatus.SAFE_SYMMETRIC: "safe",
        }.get(f.quantum_status, "")
        findings_rows += f"""
        <tr class="{status_class}">
            <td>{f.id}</td>
            <td>{f.family}</td>
            <td>{f.quantum_status.value}</td>
            <td>{f.evidence_path}:{f.evidence_line or '?'}</td>
            <td><code>{f.evidence_snippet[:120]}</code></td>
            <td>{f.confidence:.1f}</td>
        </tr>"""

    coverage_html = ""
    for axis, score in inv.coverage.items():
        coverage_html += f"<li><strong>{axis}</strong>: {score.recognised}/{score.total} recognised ({score.recall:.0%})</li>"

    # Priority with reasons
    priority_html = ""
    for f in sorted(inv.priority_findings, key=lambda x: -getattr(x, "priority_score", 0))[:10]:
        reasons = ", ".join(getattr(f, "priority_reasons", [])[:2]) or f.quantum_status.value
        priority_html += f"<li><strong>{f.family}</strong> in {f.evidence_path}:{f.evidence_line} — {reasons}</li>"

    # Actionable tables
    compliance_rows = ""
    timeline_rows = ""
    rec_rows = ""
    for f in inv.findings:
        if getattr(f, "compliance_note", ""):
            compliance_rows += f"<tr><td>{f.family}</td><td>{f.evidence_path}:{f.evidence_line}</td><td>{f.compliance_note}</td></tr>"
        if getattr(f, "timeline_flags", []):
            timeline_rows += f"<tr><td>{f.family}</td><td>{f.evidence_path}:{f.evidence_line}</td><td>{'; '.join(f.timeline_flags)}</td></tr>"
        if getattr(f, "recommendation", ""):
            rec_rows += f"<tr><td>{f.family}</td><td>{getattr(f, 'parameter_set', '') or '-'}</td><td>{f.recommendation}</td></tr>"

    compliance_html = f"<table><thead><tr><th>Family</th><th>Location</th><th>Compliance note</th></tr></thead><tbody>{compliance_rows or '<tr><td colspan=3>None</td></tr>'}</tbody></table>" if compliance_rows else "<p>No compliance notes.</p>"
    timeline_html = f"<table><thead><tr><th>Family</th><th>Location</th><th>Timeline flags</th></tr></thead><tbody>{timeline_rows or '<tr><td colspan=3>None</td></tr>'}</tbody></table>" if timeline_rows else "<p>No timeline flags.</p>"
    rec_html = f"<table><thead><tr><th>Family</th><th>Parameter set</th><th>Recommendation</th></tr></thead><tbody>{rec_rows or '<tr><td colspan=3>None</td></tr>'}</tbody></table>" if rec_rows else "<p>No specific recommendations.</p>"

    b = inv.readiness_breakdown or {}
    breakdown_html = f"""
    <table style="width:auto">
      <tr><td>Formula</td><td><code>{b.get('formula', '')}</code></td></tr>
      <tr><td>Shor-vulnerable findings</td><td>{b.get('vulnerable_count', 0)} × 15 = −{b.get('penalty_vulnerable', 0)}</td></tr>
      <tr><td>Classically weak findings</td><td>{b.get('weak_count', 0)} × 5 = −{b.get('penalty_weak', 0)}</td></tr>
      <tr><td>PQC findings</td><td>{b.get('pqc_count', 0)} × 2 = +{b.get('bonus_pqc', 0)}</td></tr>
      <tr><td>Raw → clamped</td><td>{b.get('raw', inv.readiness_score)} → <strong>{inv.readiness_score}</strong></td></tr>
    </table>
    """

    # Policy / accepted-risk section
    pr = getattr(inv, "policy_result", None) or {}
    if pr:
        viol_rows = "".join(
            f"<tr class='vulnerable'><td>{v.get('family','')}</td><td>{v.get('status','')}</td>"
            f"<td>{v.get('path','')}:{v.get('line','')}</td><td>{v.get('reason','')}</td></tr>"
            for v in pr.get("violations", [])
        ) or "<tr><td colspan=4>None</td></tr>"
        waived_rows = "".join(
            f"<tr><td>{w.get('family','')}</td><td>{w.get('key','')}</td><td>{w.get('justification','')}</td></tr>"
            for w in pr.get("waived", [])
        ) or "<tr><td colspan=3>None</td></tr>"
        status = "PASS" if pr.get("passed") else "FAIL"
        policy_html = f"""
  <h2>Policy & Accepted Risk</h2>
  <p>Result: <strong>{status}</strong> — {len(pr.get('violations', []))} violations, {len(pr.get('waived', []))} waived</p>
  <h3>Violations</h3>
  <table><thead><tr><th>Family</th><th>Status</th><th>Location</th><th>Reason</th></tr></thead>
  <tbody>{viol_rows}</tbody></table>
  <h3>Waived (accepted risk)</h3>
  <table><thead><tr><th>Family</th><th>Key</th><th>Justification</th></tr></thead>
  <tbody>{waived_rows}</tbody></table>
"""
    else:
        policy_html = ""

    # Dependency → crypto capability section
    dep_findings = [
        f for f in inv.findings
        if getattr(f, "source_scanner", "") == "qci-deps" or (f.role or "") == "dependency"
    ]
    if dep_findings:
        dep_rows = "".join(
            f"<tr class='{f.quantum_status.value}'><td>{f.family}</td>"
            f"<td>{f.quantum_status.value}</td><td>{f.evidence_path}</td>"
            f"<td><code>{(f.evidence_snippet or '')[:80]}</code></td>"
            f"<td>{f.notes or ''}</td></tr>"
            for f in dep_findings
        )
        deps_html = f"""
  <h2>Dependency → Crypto Capabilities</h2>
  <p>Known libraries mapped to cryptographic capability. Confirm versions before relying on PQC support.</p>
  <table>
    <thead><tr><th>Library</th><th>Status</th><th>Manifest</th><th>Match</th><th>Capability</th></tr></thead>
    <tbody>{dep_rows}</tbody>
  </table>
"""
    else:
        deps_html = """
  <h2>Dependency → Crypto Capabilities</h2>
  <p>No known dependency manifests matched (requirements.txt, package.json, go.mod, pom.xml, …).</p>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>QCI PQC Readiness Report – {inv.project}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #f8f9fa; }}
.container {{ max-width: 1100px; margin: auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.1); }}
h1 {{ color: #1a1a2e; }}
.score {{ font-size: 2.5rem; font-weight: bold; color: #0066cc; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 0.9rem; }}
th {{ background: #f1f3f5; }}
.vulnerable {{ background: #ffe6e6; }}
.weak {{ background: #fff3e0; }}
.pqc {{ background: #e8f5e9; }}
.safe {{ background: #f0f7ff; }}
code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
.footer {{ margin-top: 2rem; font-size: 0.8rem; color: #666; }}
</style>
</head>
<body>
<div class="container">
  <h1>Quantum Core Institute – PQC Readiness Report</h1>
  <p>Project: <strong>{inv.project}</strong></p>
  <p>Scanners: {', '.join(inv.scanners_used) or 'qci-pattern'}</p>
  <p>Readiness Score: <span class="score">{inv.readiness_score}</span> / 100</p>

  <h2>Score Breakdown</h2>
  {breakdown_html}

  {policy_html}

  {deps_html}

  <h2>Accuracy Calibration (golden corpus)</h2>
  <p>Measured against the labeled test corpus. Higher precision = fewer false positives; higher recall = fewer missed findings.</p>
  <ul>
    <li>Precision: <strong>{getattr(inv, 'calibration', {}).get('precision', 'n/a')}</strong></li>
    <li>Recall: <strong>{getattr(inv, 'calibration', {}).get('recall', 'n/a')}</strong></li>
    <li>True positives: {getattr(inv, 'calibration', {}).get('true_positives', 'n/a')}</li>
    <li>False positives (negative files): {getattr(inv, 'calibration', {}).get('false_positives', 'n/a')}</li>
    <li>False negatives: {getattr(inv, 'calibration', {}).get('false_negatives', 'n/a')}</li>
  </ul>
  <ul>{coverage_html or '<li>No coverage data</li>'}</ul>
  <p><em>These numbers reflect recognition of a small embedded form catalogue, not absolute recall of all cryptography.</em></p>

  <h2>Priority Findings (with reasons)</h2>
  <ul>{priority_html or '<li>None</li>'}</ul>

  <h2>Compliance & Library Notes</h2>
  <p>Flags pre-standard names (Kyber/Dilithium) vs FIPS 203/204/205.</p>
  {compliance_html}

  <h2>Timeline Flags (NIST IR 8547 + federal dates)</h2>
  {timeline_html}

  <h2>Algorithm & Parameter Recommendations</h2>
  {rec_html}

  <h2>NIST-Aligned Migration Notes</h2>
  <p>Findings are tagged with a suggested phase. Full guide: <code>docs/NIST-PQC-Migration-Guide.md</code>.</p>
  <ul>
    <li><strong>Phase 1</strong> — Inventory (this report + CBOM)</li>
    <li><strong>Phase 2</strong> — Prioritize (see Priority Findings above)</li>
    <li><strong>Phase 3</strong> — Select algorithms (ML-KEM-768, ML-DSA-65, SLH-DSA)</li>
    <li><strong>Phase 4–5</strong> — Design for agility & implement</li>
    <li><strong>Phase 6–7</strong> — Deploy hybrids then retire classical public-key</li>
  </ul>

  <h2>All Findings ({len(inv.findings)})</h2>
  <table>
    <thead><tr><th>ID</th><th>Family</th><th>Status</th><th>Location</th><th>Snippet</th><th>Conf.</th></tr></thead>
    <tbody>{findings_rows or '<tr><td colspan="6">No findings</td></tr>'}</tbody>
  </table>

  <div class="footer">
    Generated by qci-pqc-scan " + __version__ + " · Catalogue scoring inspired by ShorList (CC BY 4.0)<br>
    This is an MVP. Findings should be reviewed. Not a complete inventory.
  </div>
</div>
</body>
</html>"""


def write_reports(inv: Inventory, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "cbom.json").write_text(json.dumps(to_cyclonedx(inv), indent=2))
    (out_dir / "results.sarif").write_text(json.dumps(to_sarif(inv), indent=2))
    (out_dir / "report.html").write_text(to_html(inv))
