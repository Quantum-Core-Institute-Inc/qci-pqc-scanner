# Product migration guide

How to move from an earlier release of QCI Crypto Inventory to 2.3.3. This is not the algorithm migration. That is in [NIST-PQC-Migration-Guide.md](NIST-PQC-Migration-Guide.md).

## What still works

| From | What happens |
|------|--------------|
| 1.x baseline | Loads. Artifact findings are new, not regressions. |
| 2.0 or 2.1 scan | Same CLI. `qci-pqc scan <path> --out <dir>` |
| CBOM consumers | Still CycloneDX 1.6 |
| Metadata file | Still owner, system, data lifetime |

## What changed

| Version | Change | What you do |
|---------|--------|-------------|
| 2.3.1 | A waiver names the path, not the basename | Rewrite waiver keys as `family\|path\|parameter\|snippet` |
| 2.3.1 | An empty inventory is not scored | Treat a missing score as not scored, not as 100 |
| 2.3.2 | A partial scan exits 1 | A skipped archive or a failed adapter fails the gate |
| 2.3.2 | The manifest hashes the final files | Compare hashes after the run, not during it |
| 2.3.3 | A run without a policy drops the old policy file | Do not keep a stale `policy-result.json` in the output directory |

## Waiver keys

Before 2.3.1 a waiver for `crypto.py` covered every file with that name. It now names the relative path.

```json
{
  "accepted": [
    {
      "key": "RSA|payments/crypto.py|2048|",
      "owner": "payments",
      "justification": "Migrating in Q3",
      "expires": "2027-03-31"
    }
  ]
}
```

A waiver without an owner or a reason is a violation. An expired waiver is a violation.

## The gate

| Condition | Exit |
|-----------|------|
| A policy violation | 1 |
| A partial scan | 1 |
| A vulnerable finding with `--fail-on vulnerable`, and no waiver | 1 |
| A clean, complete scan | 0 |

A partial scan is not a clean scan. Check `scan-coverage.json` for what was skipped.

## The evidence

The manifest names the scanner build, the input revision, and the policy result. It hashes only the files this run wrote. A repeated run in the same directory replaces the previous files. It does not keep the previous policy result.

Archive the output directory with the manifest. The hashes are the evidence.

## What this release does not change

| | |
|--|--|
| The algorithms it finds | RSA, ECDSA, Ed25519, DH, MD5, SHA-1, DES, and the PQC replacements |
| The CLI | `qci-pqc scan` and `pql-cli scan` |
| The CBOM schema | CycloneDX 1.6 |
| Baselines | 1.x baselines still load |
