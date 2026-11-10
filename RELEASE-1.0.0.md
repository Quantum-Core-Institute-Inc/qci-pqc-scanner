# qci-pqc-scan 1.0.0

1.0.0 is the first release meant to be run as a gate, not only as a report.

## What 1.0 is

- A source and config scanner for cryptographic inventory.
- CycloneDX 1.6 CBOM, SARIF, and an HTML report.
- `pql-cli` for scan, diff, gate, org inventory, and trend.
- Policy-as-code. A vulnerable finding without an accepted risk fails the build. An exception needs an owner, a reason, and an expiry.
- A regression gate. A new finding that is not in the baseline fails the pull request.
- Scheduled scans.
- TLS 1.3 cipher suite names, Go ML-KEM sizes, and dependency PQC thresholds.

Measured on CBOM testbench v12, seed `20261110`:

| Metric | Value |
|--------|------:|
| Recall | 72.9% |
| Precision | 100% |
| Parameters | 72.7% |
| Ticket-ready | 61.5% |
| False positives | 0 |
| PQC over-claims | 0 |
| Holdout recall | 85.9% |

## What 1.0 is not

- Not complete coverage. 72.9% recall is the share of the v12 corpus that was found. It is not a statement about a real repository.
- Not a guarantee on code it has not seen. Holdout recall is 85.9% on the same shapes, not on hand-rolled crypto.
- Not Tier 5. String assembly, reflection, base64 names, and hand-rolled algorithms are out of scope.
- Not a dependency scanner in the cdxgen sense. Versions are recorded for the libraries it knows. It does not resolve a full lockfile tree.
- Not a formal assurance product.

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) before treating a score as coverage.
