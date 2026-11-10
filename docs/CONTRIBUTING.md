# Contributing

## Required CI on `main`

Pull requests must pass the **test** check before merge.

The check is defined in `.github/workflows/ci.yml` and runs:
- Golden corpus tests
- Calibration gate (recall ≥ 0.9, zero false positives on negative files)
- CBOM schema validation
- Version consistency

### Enable the requirement (repo admin)

1. Settings → Branches → Add branch protection rule (or Rules → Rulesets)
2. Branch name pattern: `main`
3. Enable **Require status checks to pass before merging**
4. Select the **test** check
5. Optionally enable **Require branches to be up to date before merging**
6. Save

Do not push feature work directly to `main`.
