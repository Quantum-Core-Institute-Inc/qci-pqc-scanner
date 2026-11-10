# qci-pqc-scan 1.1.0

1.1.0 is 1.0 measured against more of the world. It is not a new detection class.

## What changed

- Customer-shaped corpus, so published numbers can move with shipped code.
- Same-line parameters for AES size, RSA size, EC curve, and HMAC hash.
- Adapter maps for names 1.0 already detects.
- Baseline and exception keys no longer use the line number.
- Operator guide corrections for fields that were misread.

## Measured

CBOM testbench v12, seed `20261110`, after the 1.1 changes:

| Metric | Value |
|--------|------:|
| Recall | 72.9% |
| Precision | 100% |
| Parameters | 72.7% |
| Ticket-ready | 61.5% |
| False positives | 0 |
| PQC over-claims | 0 |

Precision and over-claims held. Recall is not claimed higher than 1.0.

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md). It is still true.
