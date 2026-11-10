# qci-pqc-scan 2.1.0

2.1 finishes 2.0. It is not a new detection class.

## What changed

- The artifact corpus grew. A JAR and a signing class sit next to the original class file.
- Artifact precision and recall are published on their own. They are not added to source recall.
- Provenance is on every path: source, config, dependency, or artifact.
- Cross-module resolution is exercised on a package-shaped fixture, not only a unit test.
- A 1.x baseline still loads. An artifact finding is not a regression.
- The operator guide says not to add the two scores.

## Not in 2.1

- Obfuscated or packed code
- A value that exists only at deploy time
- Live traffic
- One recall number that hides the artifact gap

## Done when

The artifact corpus has its own precision and recall, provenance is on every finding, and a 1.x baseline still loads without calling an artifact a regression.

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
