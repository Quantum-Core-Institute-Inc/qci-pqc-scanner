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
