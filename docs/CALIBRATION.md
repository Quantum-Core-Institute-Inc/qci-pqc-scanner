# Published calibration results (golden corpus)

| Date | Corpus files | Recall | Precision | FP (negative files) | Notes |
|------|--------------|--------|-----------|---------------------|-------|
| 2026-11-10 | tests/corpus (expanded) | 1.0 | ~0.76–0.83 | 0 | Comment stripping enabled |

Run:
```bash
qci-pqc scan tests/corpus --calibrate
qci-pqc scan tests/corpus --calibrate --json > calibration.json
```

These figures are for the included corpus only. See docs/LIMITATIONS.md.
