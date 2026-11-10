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

## Tier 2/3 indirection

In scope:
- JSON and `.properties` configs that name an algorithm
- Literal arguments to crypto calls (`digest("MD5")`, `getInstance("AES/ECB")`)
- File-local and cross-file string constants

Out of scope, by design:
- Dependency injection where the algorithm is chosen only at runtime
- Strategy factories whose choice is not a literal in the scanned tree
- Values that exist only in an environment at deploy time, with no default in the repo

A static scanner cannot know a choice that is not written down.

## v1.1 does not change this page

1.1 adds customer-shaped cases, finishes parameters inside the existing scope, and credits names 1.0 already detects. It does not add a detection class.

- Tier 5, compiled code, and obfuscation stay out of scope.
- Recall is still the published corpus number. A higher number on a new corpus is not a higher claim.
- Precision 100% and zero PQC over-claims remain the gates. If either moves, 1.1 is not done.
