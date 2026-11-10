# qci-pqc-scan 2.0.0

2.0 is a new scope, not a better 1.0.

## What changed

- Compiled artifacts are scanned. JARs and class files, by strings.
- A constant defined in another file of the same tree is followed.
- Source and artifact counts are printed separately. They are not blended.
- Each CBOM component says source, config, or artifact.
- The 1.0 limitations page is retired. See docs/LIMITATIONS.md.
- A 1.x baseline still loads. Artifact findings are not regressions.

## Not in 2.0

- Obfuscated or packed code.
- A value that exists only at deploy time.
- One recall number that hides the artifact gap.

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
