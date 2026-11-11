from qci_pqc.models import Finding, QuantumStatus
from qci_pqc.policy import finding_key
from qci_pqc.dedupe import deduplicate

def _f(path, snippet, line=0):
    return Finding(id="x", evidence_path=path, evidence_line=line, evidence_snippet=snippet,
                   family="RSA", quantum_status=QuantumStatus.VULNERABLE, role="sign",
                   source_scanner="qci-artifact", confidence=0.8)

def test_waiver_does_not_cross_files():
    a = _f("payments/crypto.py", "rsa", line=10)
    b = _f("identity/crypto.py", "rsa", line=10)
    assert finding_key(a) != finding_key(b)

def test_two_classes_in_one_jar_stay_two():
    a = _f("app.jar", "app.jar!Pay.sign: SHA256withRSA")
    b = _f("app.jar", "app.jar!Id.sign: SHA256withRSA")
    assert len(deduplicate([a, b])) == 2
