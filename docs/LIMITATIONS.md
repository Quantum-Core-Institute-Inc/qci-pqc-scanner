# Limitations

This scanner is a pattern-based cryptographic inventory tool. It is **not** a complete assurance product.

## In scope
- Source-code and configuration pattern matching for common cryptographic APIs
- PEM certificate / private-key presence and basic type detection
- TLS (nginx/Apache) and SSH (`sshd_config`) configuration signals
- NIST PQC algorithm name detection (ML-KEM, ML-DSA, SLH-DSA, hybrids)
- Readiness scoring, prioritization heuristics, and CycloneDX CBOM export

## Out of scope
- Full X.509 parsing (signature algorithm, key size, validity period, chain validation)
- Runtime or dynamic analysis
- Binary / JAR / container image scanning
- Complete dependency-to-crypto-capability mapping
- Formal verification or cryptographic correctness proofs
- Guarantee of zero false positives or zero false negatives outside the golden corpus

## Accuracy
Measured on the included golden corpus (`tests/corpus`):
- Recall: 1.0
- Precision: 0.744
- False positives on designated negative files: 0
- Expected positives: 32

These numbers do **not** transfer automatically to arbitrary codebases.

## Recommendations
- Treat findings as leads for human review.
- Use `--ignore` and baselines to track accepted risk.
- Re-run with `--reproducible` when evidence must be repeatable.
- Keep the ruleset hash (`evidence-manifest.json`) with any archived report.
