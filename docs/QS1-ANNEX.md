# QS1 evidence annex

This annex attaches a QCI scan to a QCI-QS1 assessment. It is discovery output. It is not a validated inventory and it is not the QS1 readiness score.

Cite the standard as: Quantum Core Institute. QCI-QS1 Quantum Readiness and Post-Quantum Cryptography Governance Standard. Version 2.3. September 23, 2026.

## 1. Identification

| Field | Value |
|-------|-------|
| Organization | |
| System or critical flow | |
| Accountable owner | |
| Technical reviewer | |
| Assessment date | |
| Scanner version | |
| Input revision | |
| Scan date | |

## 2. What this is

| QS1 term | This annex |
|----------|------------|
| Discovery output | The findings in `findings.json` |
| Scan reach | `scan-coverage.json`: files read, parsers used, skipped |
| CBOM | `cbom.json`, CycloneDX 1.6 |
| Evidence | `evidence-manifest.json`: build, revision, hashes |

Scan reach is not coverage. QCI-5.1-03: scan reach shall never replace the coverage metrics.

## 3. Scan reach

| | |
|--|--|
| Files read | |
| Parsers used | |
| Skipped, and why | |
| Partial | Yes / No |
| Gate result | Exit 0 / Exit 1 |

A partial scan is not evidence of a clean tree. It is evidence that the scan did not finish.

## 4. Findings

| Family | Status | Path | Line | Parameter | Owner | Lifetime |
|--------|--------|------|------|-----------|-------|----------|
| | | | | | | |

Status is the scanner's classification: vulnerable, weak, safe symmetric, PQC, hybrid, or unknown. It is not a QS1 exposure determination.

## 5. Exposure flags the scanner can support

| QS1 flag (QCI-5.3-01) | Scanner evidence |
|------------------------|------------------|
| Vulnerable protection of long-lived confidentiality | Findings with status vulnerable, plus data lifetime if supplied |
| Unknown algorithm or profile | Findings with status unknown, or a parameter that is empty |
| Missing ownership or evidence | Owner field empty |
| Inadequate discovery provenance | Partial scan, or a skipped parser |

An approved migration plan does not clear a flag. The scanner does not clear one either.

## 6. What this annex is not

| QS1 requires | Why this annex does not provide it |
|--------------|------------------------------------|
| Validated inventory record | Needs an owner and a technical reviewer confirming identity, links, and freshness |
| System and critical-flow coverage | Needs an identified population. The scanner has a tree. |
| The QS1 readiness score | QS1 scores maturity across pillars. The scanner scores findings. |
| Supplier conformance | Name matching does not show the same implementation or version |
| Freshness under 90 days | The scanner does not know when a finding was last reviewed |

## 7. Reviewer confirmation

| | |
|--|--|
| Reviewer | |
| Date | |
| Confirmed identity and dependency links | Yes / No |
| Confirmed evidence is relevant and current | Yes / No |
| Unknown values left explicit | Yes / No |
| Disposition | Validated / Incomplete / Not applicable, with rationale |

Owner acknowledgement alone does not verify unknown cryptographic attributes. A record with an unknown algorithm, parameter, or key-protection mechanism shall not count as validated coverage.
