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

## Fields operators misread

| Field | Means | Does not mean |
|-------|-------|----------------|
| `parameterSetIdentifier` | The size, curve, or mode on that line | A size guessed from elsewhere in the file |
| `nistQuantumSecurityLevel` 0 | Quantum-vulnerable | Broken or weak classically |
| `qci:riskCategory` | A dashboard label such as DH/ECDH | The algorithm name |
| Recall | Share of the published corpus that was found | Coverage of your repository |
| A new finding in `diff` | Family, file, and parameter were not in the baseline | A line moved |

An exception needs an owner, a reason, and an expiry. An expired exception fails the build even if the finding did not change.

## Source score and artifact score

Do not add them.

| Score | Counts | Does not count |
|-------|--------|----------------|
| Source | Source and config findings | JARs, class files, binaries |
| Artifact | Class pool, JAR, WAR, wheel, image, ELF, PE | Source recall |

A high source score says nothing about the JAR. A high artifact score says nothing about the source. 2.3 prints both and does not blend them.


## What the file is

The product is a crypto inventory. `cbom.json` is a CycloneDX file. It is not a complete bill of materials: it does not say what breaks when you change an algorithm.

## Dependency graph

`report.html` has a Dependency graph section. `graph.json` has the same edges: app, library, finding, path.

## Fields from metadata

| Field | From |
|-------|------|
| `qci:owner` | metadata `owner` |
| `qci:system` | metadata `system` |
| `qci:dataLifetime` | metadata `data_lifetime` |
| `qci:agility` | `config` if the finding came from config, otherwise `code` |

A purl is recorded on a dependency when a version was found. A KMS or HSM label in a file is recorded. The scanner does not call the KMS or the HSM.
