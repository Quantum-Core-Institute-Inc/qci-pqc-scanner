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


## External corpus (QCI CBOM Benchmark)

Version 2.3.4.3, measured on [QCI CBOM Benchmark](https://github.com/Quantum-Core-Institute-Inc/CBOM-Benchmark) 2.6.5.1: 410 findings across seven languages, certificates, keys, configs and compiled code.

| Metric | In declared scope | Everything |
|--------|------:|------:|
| Recall | 65.5% | 62.2% |
| Precision | 100% | 100% |
| Parameters correct (of detected) | 90.8% | 90.2% |
| Ticket-ready (of detected) | 81.3% | 80.0% |
| False positives | 0 | 0 |
| PQC over-claims | 0 | 0 |
| Holdout recall, matched cells | 68.2% | |
| Overfit gap | -0.8 (95% interval -5.6 to +4.2) | |

These are the figures for the last version the benchmark has measured. Later versions are measured when the benchmark cuts a release against them; until then they have no external number.

The corpus is larger and harder than the v12 corpus the older figures below were taken on, so the two sets of numbers are not comparable. Recall went down between them because the denominator grew, not because the scanner found less.

Quantum Core Institute writes both the scanner and the benchmark. The benchmark publishes the evidence bundle for this run (`evidence/qci-v2.3.4.3`); `python tools/bench.py verify` re-derives the score from the scanner's raw output.

Reproduce, in a checkout of the benchmark, with a private holdout seed:

```bash
QCI_BIN=/path/to/venv/bin/qci-pqc CDXGEN_BIN=/path/to/cbom CBOM_HOLDOUT_SEED=<seed> tools/release_run.sh
```

The golden corpus is `tests/corpus`. The external corpus is the QCI CBOM Benchmark.

## Customer-shaped corpus

`tests/corpus/customer` is code shaped like what operators ship: AES-GCM and RSA-2048 in a payment helper. It is not a copy of the testbench. Add a file here when a customer miss is fixed, so the published numbers move with real code.

## History: v1.1 re-score (testbench v12)

Seed `20261110`. Adapter copied from this repo.

| Metric | Value |
|--------|------:|
| Recall | 72.9% |
| Precision | 100% |
| Parameters | 72.7% |
| Ticket-ready | 61.5% |
| False positives | 0 |
| PQC over-claims | 0 |
| Holdout recall | 85.9% |
| Overfit gap | +2.0 |

Precision and over-claims held. Recall is unchanged from 1.0.

## Artifact corpus (2.0 class)

Separate from the source corpus. Do not add these numbers to source recall.

| Corpus | Expected | Notes |
|--------|----------|-------|
| `tests/corpus/artifacts` | AES in Pay.class, AES in pay.jar, RSA in Sign.class | Strings in compiled files |

Precision gate for this corpus is 1.0. A false positive here fails 2.1.
