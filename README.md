# QCI PQC Readiness Scanner

CLI tool for cryptographic inventory and post-quantum readiness assessment.

**Version:** 0.2.0  
**License:** MIT (see LICENSE)  
**Coverage scoring** inspired by ShorList (CC BY 4.0).

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for scope, accuracy bounds, and what the scanner does not do.

## Install

```bash
pip install -e .
# or
docker build -t qci-pqc-scan .
docker run --rm -v $(pwd):/work qci-pqc-scan scan /work --out /work/reports
```

## Quick start

```bash
qci-pqc scan /path/to/code --out reports
```

See [docs/OPERATOR.md](docs/OPERATOR.md) for compliance workflow, offline use, and evidence handling.

## Algorithm references

- [`docs/ML-DSA.md`](docs/ML-DSA.md) — ML-DSA (FIPS 204) post-quantum signatures
- [`docs/NIST-PQC-Migration-Guide.md`](docs/NIST-PQC-Migration-Guide.md) — Migration steps

See [`docs/NIST-PQC-Migration-Guide.md`](docs/NIST-PQC-Migration-Guide.md) for a short operational summary aligned with:

- NIST IR 8547 (Transition to Post-Quantum Cryptography Standards, Oct 2026)
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- CSWP 39 (Crypto Agility)

```bash
# Print calibration metrics only (no report)
qci-pqc scan tests/corpus --calibrate
```

Measured on the golden corpus (`tests/corpus`):

- **Recall:** 1.0 (all expected positive findings detected)
- **Precision:** ~0.73 (some false positives remain, mainly on negative/comment files)
- Run: `PYTHONPATH=src python -m pytest tests/test_calibration.py`

The HTML report includes a calibration section when scanning the corpus.

## Certificate & config inventory

Detects PEM certificates/keys, nginx/Apache TLS settings, OpenSSL config, `sshd_config` (including PQC hybrid KEX), and Java TLS policy properties.  
Sample files: `tests/corpus/nginx.conf`, `tests/corpus/sshd_config`.

`cbom.json` is CycloneDX 1.6 with:
- `$schema` and `serialNumber` (URN UUID)
- `cryptoProperties` (`assetType`, `algorithmProperties.primitive`, `parameterSetIdentifier`)
- Known NIST OIDs for ML-KEM / ML-DSA / SLH-DSA where applicable
- Evidence locations and QCI properties (quantum status, priority, timeline)

```bash
# Ignore known exceptions
PYTHONPATH=src python -m qci_pqc.cli scan /path --ignore ignore.txt

# Baseline / history
PYTHONPATH=src python -m qci_pqc.cli scan /path --save-baseline baseline.json
PYTHONPATH=src python -m qci_pqc.cli scan /path --baseline baseline.json

# Tag with owner / system / data lifetime
PYTHONPATH=src python -m qci_pqc.cli scan /path --metadata meta.json

# Export tickets for GRC tools + evidence manifest
PYTHONPATH=src python -m qci_pqc.cli scan /path --tickets
```

Outputs now include `findings.json`, `tickets.json`, and `evidence-manifest.json` (with SHA-256 hashes).  
Certificate, TLS config, and PQC-dependency patterns are also detected.

The scanner now includes:
- Parameter-set validation notes (ML-KEM-768, ML-DSA-65, ML-DSA-87)
- Pre-standard vs FIPS name checks (Kyber/Dilithium)
- Role-aware timeline flags (key establishment vs signatures)
- Hybrid construction validation notes
- Expanded library patterns (OpenSSL-style, liboqs, Java, Go CIRCL)
- Negative test cases in the golden corpus for false-positive control

- Priority findings with reasons (root CA, external, long-lived heuristics)
- Compliance notes (pre-standard Kyber/Dilithium vs FIPS names)
- Timeline flags (2030/2035 IR 8547 + federal 2030/2031 dates)
- Algorithm & parameter-set recommendations
- Phase tagging for the migration process
- Hybrid detection notes

The scanner recognises NIST-standardized and common post-quantum algorithms:

| Algorithm | Standard | Role | Former name |
|-----------|----------|------|-------------|
| ML-KEM (512/768/1024) | FIPS 203 | Key encapsulation | Kyber |
| ML-DSA (44/65/87) | FIPS 204 | Digital signatures | Dilithium |
| SLH-DSA | FIPS 205 | Hash-based signatures | SPHINCS+ |
| FN-DSA | FIPS 206 (draft) | Compact signatures | Falcon |
| HQC, Classic McEliece, BIKE | Candidates / backups | KEM | — |
| Hybrids (e.g. X25519+ML-KEM) | — | Transition | — |

Parameter sets and common library names are matched. PQC findings receive a small positive credit in the readiness score.

Transparent formula shown in every HTML report:

```
score = clamp(0, 100, 100 - (vulnerable × 15) - (weak × 5) + (pqc × 2))
```

- Vulnerable = Shor-vulnerable public-key (RSA, ECDSA, etc.)
- Weak = classically broken or deprecated (MD5, SHA-1, DES, …)
- PQC = post-quantum algorithm references

The report includes the exact counts and arithmetic so the number can be audited.

```bash
pip install pytest
PYTHONPATH=src python -m pytest tests/test_corpus.py -v
```

The corpus in `tests/corpus/` contains known cryptographic forms.  
`tests/expected/*.json` asserts that key findings must still be present after changes to patterns, rules, or deduplication.

When multiple adapters are used (or the same form is found nearby), findings are merged if they share:
- Normalized algorithm family
- Same filename
- Line numbers within a small window

The merged finding keeps the highest confidence and lists all contributing scanners.

## Adapters

- `internal` / `qci-pattern` — Built-in pattern scanner (expanded set: Python, Java, Go, JS, C/OpenSSL, PEM, SSH/TLS configs, PQC names, simple defects).
- `cryptoscan` — Wrapper for the open-source [csnp/cryptoscan](https://github.com/csnp/cryptoscan) tool. Falls back to internal if the binary is not found.
- `qscan` — Wrapper for [@quantakrypto/qscan](https://github.com/quantakrypto/pqc-tools) (runs via `npx`, Node ≥ 20). Multi-language quantum-vulnerable crypto discovery.
- `semgrep` — Wrapper for Semgrep using focused QCI crypto rules (`src/qci_pqc/rules/crypto.yml`). Higher precision via AST matching. Install with `pip install semgrep`.

## What it does

- Pattern-based scanning (or external scanner via adapter) of source and config for cryptographic forms.
- Classifies findings as Shor-vulnerable, classically weak, PQC, hybrid, or safe symmetric.
- Computes a simple readiness score and priority list.
- Scores the scanner against a small embedded form catalogue (inspired by [ShorList](https://github.com/shorlist/shorlist), CC BY 4.0).
- Outputs standard formats useful for security engineers and CI.

## What it does not do (MVP limits)

- Not a complete cryptographic inventory.
- Not data-flow analysis.
- Not a full integration of external scanners yet (architecture supports adapters).
- Coverage numbers are relative to a small embedded set, not absolute recall.

## Attribution

Coverage scoring approach and form concept inspired by ShorList (Stanimir Tenev, CC BY 4.0).  
https://github.com/shorlist/shorlist · https://doi.org/10.5281/zenodo.23974515

## License

Apache-2.0 (code). Catalogue-inspired data follows ShorList attribution requirements.
