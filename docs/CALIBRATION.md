# Published calibration results

Measured on the golden corpus in `tests/corpus`.

| Date | Expected positives | True positives | Recall | Precision | FP (negative files) | Total findings |
|------|--------------------|----------------|--------|-----------|---------------------|----------------|
| 2026-11-10 | 32 | 32 | **1.0** | **0.744** | **0** | 97 |

## How to reproduce

```bash
qci-pqc scan tests/corpus --calibrate
qci-pqc scan tests/corpus --calibrate --json
```

## Corpus contents

- Positive: Python, Java, Go, JavaScript, PEM, PQC libraries, TLS config
- Negative: comments, documentation, safe-only files
- Real-world style: liboqs, CIRCL, BouncyCastle-style, OpenSSL-style names

## Scope

These numbers apply to this corpus only. They do not transfer automatically to arbitrary codebases. See [LIMITATIONS.md](LIMITATIONS.md).


## External corpus (testbench v12)

| Metric | Value |
|--------|------:|
| Recall | 69.2% |
| Precision | 100% |
| Parameters | 71.2% |
| Ticket-ready | 61.4% |
| False positives | 0 |
| PQC over-claims | 0 |
| Holdout recall | 84.8% |
| Overfit gap | +0.5 |

Reproduce with `CBOM_HOLDOUT_SEED` set:

```bash
CBOM_HOLDOUT_SEED=20261110 python3 tools/run_qci_pqc.py --qci-bin qci-pqc --no-gate
```

The golden corpus is `tests/corpus`. The external corpus is the CBOM testbench.

## Customer-shaped corpus

`tests/corpus/customer` is code shaped like what operators ship: AES-GCM and RSA-2048 in a payment helper. It is not a copy of the testbench. Add a file here when a customer miss is fixed, so the published numbers move with real code.
