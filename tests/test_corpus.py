"""Golden corpus tests for QCI PQC scanner adapters."""

import json
from pathlib import Path

import pytest

from qci_pqc.adapters import get_adapter
from qci_pqc.dedupe import deduplicate

CORPUS = Path(__file__).parent / "corpus"
EXPECTED = Path(__file__).parent / "expected"


def _normalize_family(family: str) -> str:
    f = family.lower()
    if "rsa" in f:
        return "rsa"
    if "ecdsa" in f or f == "ec":
        return "ecdsa"
    if "md5" in f:
        return "md5"
    if "sha-1" in f or "sha1" in f:
        return "sha1"
    if "ml-kem" in f or "kyber" in f or "mlkem" in f:
        return "ml-kem"
    if "ml-dsa" in f or "mldsa" in f or "dilithium" in f:
        return "ml-dsa"
    if "slh-dsa" in f or "slhdsa" in f or "sphincs" in f:
        return "slh-dsa"
    if "fn-dsa" in f or "falcon" in f:
        return "fn-dsa"
    return f


def _run(adapter_name: str):
    adapter = get_adapter(adapter_name)
    if not adapter.available():
        pytest.skip(f"{adapter_name} not available")
    findings = deduplicate(adapter.scan(CORPUS))
    return findings


def _check(adapter_name: str):
    findings = _run(adapter_name)
    expected = json.loads((EXPECTED / f"{adapter_name}.json").read_text())

    assert len(findings) >= expected["min_findings"], (
        f"{adapter_name}: expected at least {expected['min_findings']} findings, got {len(findings)}"
    )

    actual = {
        (_normalize_family(f.family), Path(f.evidence_path).name, f.quantum_status.value)
        for f in findings
    }

    missing = []
    for req in expected["must_include"]:
        key = (req["family"], req["file"], req["status"])
        if key not in actual:
            missing.append(key)

    assert not missing, f"{adapter_name}: missing required findings: {missing}"


def test_internal_corpus():
    _check("internal")


def test_semgrep_corpus():
    _check("semgrep")
