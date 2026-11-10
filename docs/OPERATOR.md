# Operator & Auditor Guide

## Running a scan (offline)

```bash
qci-pqc scan /path/to/repo --out reports
```

No network access is required for the internal adapter.  
Semgrep / cryptoscan / qscan adapters need their binaries present locally.

## Outputs

| File | Purpose |
|------|---------|
| `report.html` | Human-readable readiness report |
| `cbom.json` | CycloneDX 1.6 CBOM |
| `results.sarif` | SARIF for CI / code scanning |
| `findings.json` | Structured findings |
| `evidence-manifest.json` | SHA-256 hashes for audit evidence |
| `tickets.json` | Optional GRC/ticket export (`--tickets`) |

## Compliance workflow

1. Establish a baseline: `--save-baseline baseline.json`
2. Subsequent scans: `--baseline baseline.json` to see new/resolved
3. Document exceptions in `ignore.txt` and pass `--ignore`
4. Attach metadata: `--metadata meta.json` (`owner`, `system`, `data_lifetime`)
5. Archive the entire output directory + `evidence-manifest.json`

## Rules versioning

- Rules live in `src/qci_pqc/scanner.py` (patterns) and `src/qci_pqc/rules/crypto.yml` (Semgrep).
- Version is tracked via the package version in `pyproject.toml`.
- When updating rules, bump the version and re-run the golden corpus.

## Security notes

- The scanner only reads files; it does not execute target code.
- Review findings before acting; pattern matching has false positives.
- Keep the scanner and its dependencies updated.

## What the score means

The readiness score is a summary of what the scanner found in the files it can read. It is not a measure of quantum safety.

| Number | Means | Does not mean |
|--------|-------|----------------|
| Recall 69.2% | Of the known findings in the v12 corpus, this share was reported | The other 30.8% of a real repo is safe |
| Precision 100% | Nothing in the negative controls was reported | Every finding is a vulnerability |
| Ticket-ready 61.4% | The finding has enough detail to open a ticket | The ticket is already approved |
| Holdout 84.8% | On code the scanner has not seen, it still finds most of the same shapes | It will find hand-rolled crypto |

Tier 5 (string assembly, reflection, hand-rolled algorithms) is out of scope. A miss there is expected.

Read [LIMITATIONS.md](LIMITATIONS.md) before treating a score as coverage.
