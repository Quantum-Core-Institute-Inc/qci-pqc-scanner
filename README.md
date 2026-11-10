# QCI PQC Readiness Scanner

**Cryptographic inventory and post-quantum readiness assessment for security teams.**

[![CI](https://github.com/Quantum-Core-Institute-Inc/qci-pqc-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Quantum-Core-Institute-Inc/qci-pqc-scanner/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6-green.svg)](https://cyclonedx.org/)

**Version:** 0.4.0  
**Author:** Quantum Core Institute  
**License:** MIT (see [LICENSE](LICENSE))

---

## What it does

`qci-pqc` scans source code and configuration for cryptographic usage, classifies findings by quantum risk, and produces:

- A **readiness score** with a transparent formula
- A **CycloneDX 1.6 CBOM** (schema-validated)
- **SARIF 2.1.0** for CI integration
- A self-contained **HTML report** with prioritization, timelines, and recommendations
- **Evidence artifacts** (manifest with ruleset hash, optional ticket export)

It is designed to support NIST IR 8547 transition planning and FIPS 203/204/205 adoption.

> **Important:** This is a pattern-based inventory tool, not a complete assurance product.  
> See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for scope and accuracy bounds.

---

## Quick start

```bash
# Install
pip install -e .

# Scan
qci-pqc scan /path/to/repo --out reports

# Open the report
open reports/report.html
```

### Docker

```bash
docker build -t qci-pqc-scan .
docker run --rm -v $(pwd):/work qci-pqc-scan scan /work --out /work/reports
```

---

## Features

| Capability | Description |
|------------|-------------|
| **Multi-adapter scanning** | Internal patterns, Semgrep, cryptoscan, qscan |
| **PQC detection** | ML-KEM, ML-DSA, SLH-DSA, FN-DSA, hybrids, pre-standard names |
| **Classical risk** | RSA, ECDSA, Ed25519, DH/ECDH, MD5, SHA-1, weak TLS/SSH |
| **Certificate & config inventory** | PEM keys/certs, nginx/Apache TLS, `sshd_config` |
| **Deduplication** | Merges overlapping findings across adapters |
| **Prioritization** | Heuristics for root CA, external-facing, long-lived data |
| **NIST alignment** | IR 8547 timelines, FIPS parameter recommendations, phase tagging |
| **Calibration** | Measured precision/recall on the golden corpus |
| **Reproducible evidence** | `--reproducible` mode with stable IDs and ruleset hash |
| **Compliance workflow** | Baselines, ignore lists, ticket export, evidence manifest |

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/Quantum-Core-Institute-Inc/qci-pqc-scanner.git
cd qci-pqc-scanner
pip install -e ".[dev]"   # includes pytest
```

Optional external scanners (adapters fall back gracefully if missing):

```bash
pip install semgrep          # Semgrep adapter
# cryptoscan binary or npx for qscan
```

---

## Usage

### Basic scan

```bash
qci-pqc scan /path/to/code --out reports
```

### Local web UI

```bash
qci-pqc serve
# open http://127.0.0.1:8080
```

Same engine as the CLI. Enter a path, run a scan, view the report in the browser.

### Common options

```bash
# Multiple adapters + deduplication
qci-pqc scan /path --adapter "internal,semgrep" --out reports

# Fail CI if Shor-vulnerable findings exist
qci-pqc scan /path --fail-on vulnerable

# Machine-readable summary
qci-pqc scan /path --json

# Verbose finding list
qci-pqc scan /path --verbose

# Calibration metrics only (no report)
qci-pqc scan tests/corpus --calibrate
qci-pqc scan tests/corpus --calibrate --json

# Reproducible / audit mode
qci-pqc scan /path --reproducible --out reports
```

### Compliance workflow

```bash
# Establish baseline
qci-pqc scan /path --save-baseline baseline.json --out reports

# Later: show new vs resolved
qci-pqc scan /path --baseline baseline.json --out reports

# Ignore accepted findings
qci-pqc scan /path --ignore ignore.txt

# Attach owner / system metadata
qci-pqc scan /path --metadata meta.json

# Export tickets for GRC tools
qci-pqc scan /path --tickets
```

`ignore.txt` format (one per line):
```
RSA|sample.py|6
MD5|CryptoExample.java
```

`meta.json` example:
```json
{
  "owner": "security-team",
  "system": "payments-api",
  "data_lifetime": "10-years"
}
```

---

## CLI reference

| Flag | Description |
|------|-------------|
| `--out`, `-o` | Output directory (default: `qci-pqc-out`) |
| `--adapter`, `-a` | `internal`, `semgrep`, `cryptoscan`, `qscan`, or comma-separated list |
| `--fail-on` | `vulnerable`, `weak`, or `none` (exit code 1) |
| `--no-dedupe` | Disable deduplication |
| `--ignore` | Ignore file |
| `--baseline` / `--save-baseline` | Diff against / write baseline |
| `--tickets` | Export `tickets.json` |
| `--metadata` | JSON with owner, system, data_lifetime |
| `--calibrate` | Print precision/recall and exit |
| `--verbose`, `-v` | Print each finding |
| `--json` | JSON summary on stdout |
| `--reproducible` | Stable IDs, no timestamps, content-addressed CBOM serial |

---

## Outputs

| File | Purpose |
|------|---------|
| `report.html` | Human-readable readiness report |
| `cbom.json` | CycloneDX 1.6 CBOM (schema-validated) |
| `results.sarif` | SARIF 2.1.0 for CI / code scanning |
| `findings.json` | Structured findings |
| `evidence-manifest.json` | SHA-256 hashes, ruleset hash, scanner version |
| `tickets.json` | Optional GRC/ticket export (`--tickets`) |

### Readiness score

```
score = clamp(0, 100, 100 - (vulnerable × 15) - (weak × 5) + (pqc × 2))
```

Shown with full breakdown in the HTML report.

---

## Architecture

```
src/qci_pqc/
├── cli.py           # Click CLI
├── adapters.py      # Pluggable scanners
├── scanner.py       # Internal pattern engine
├── rules/crypto.yml # Semgrep rules
├── dedupe.py        # Cross-adapter deduplication
├── enrich.py        # Prioritization, timelines, recommendations
├── scoring.py       # Readiness score + coverage
├── calibrate.py     # Precision/recall against golden corpus
├── certs.py         # PEM / certificate inspection
├── compliance.py    # Baseline, ignore, evidence, tickets
├── report.py        # HTML, CBOM, SARIF
└── models.py        # Finding, Inventory
```

**Adapters**
- `internal` — Built-in regex scanner (always available)
- `semgrep` — AST-based rules (`src/qci_pqc/rules/crypto.yml`)
- `cryptoscan` — Wrapper for [csnp/cryptoscan](https://github.com/csnp/cryptoscan)
- `qscan` — Wrapper for [@quantakrypto/qscan](https://github.com/quantakrypto/pqc-tools)

---

## Accuracy

Measured on the golden corpus (`tests/corpus`) — see [docs/CALIBRATION.md](docs/CALIBRATION.md):

| Metric | Value |
|--------|-------|
| Recall | **1.0** |
| Precision | **0.744** |
| True positives | 32 / 32 |
| False positives (negative files) | **0** |

```bash
qci-pqc scan tests/corpus --calibrate
PYTHONPATH=src python -m pytest tests/test_calibration.py -q
```

These numbers apply to the included corpus only. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

---

## Algorithms detected

| Algorithm | Standard | Role | Former name |
|-----------|----------|------|-------------|
| ML-KEM (512/768/1024) | FIPS 203 | Key encapsulation | Kyber |
| ML-DSA (44/65/87) | FIPS 204 | Signatures | Dilithium |
| SLH-DSA | FIPS 205 | Hash-based signatures | SPHINCS+ |
| FN-DSA | FIPS 206 (draft) | Compact signatures | Falcon |
| Hybrids (e.g. X25519+ML-KEM) | — | Transition | — |

Plus classical public-key (RSA, ECDSA, Ed25519, DH/ECDH), weak hashes (MD5, SHA-1), and TLS/SSH configuration signals.

---

## Documentation

| Document | Contents |
|----------|----------|
| [docs/OPERATOR.md](docs/OPERATOR.md) | Operator & auditor guide, offline use, evidence handling |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Scope, out-of-scope items, accuracy bounds |
| [docs/NIST-PQC-Migration-Guide.md](docs/NIST-PQC-Migration-Guide.md) | Phased migration aligned with IR 8547 |
| [docs/ML-DSA.md](docs/ML-DSA.md) | ML-DSA (FIPS 204) reference |

---

## Development

```bash
# Run tests
PYTHONPATH=src python -m pytest tests/ -q

# Calibration
qci-pqc scan tests/corpus --calibrate

# Schema-validated CBOM (requires network for schema fetch)
# See .github/workflows/ci.yml
```

CI (`.github/workflows/ci.yml`) runs:
- Golden corpus tests
- Calibration gate (recall ≥ 0.9, zero FP on negative files)
- CBOM schema validation against CycloneDX 1.6
- Reproducible smoke scan
- Version consistency check

---

## Attribution

Coverage scoring approach is inspired by [ShorList](https://github.com/shorlist/shorlist) (CC BY 4.0).  
This project is an independent implementation.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Support

For issues and feature requests, use the GitHub issue tracker.  
Quantum Core Institute — PQC readiness tooling.
