# Limitations (2.0)

The 1.0 page is retired. This is the ceiling.

## In scope
- Source and configuration, as in 1.x
- Compiled artifacts: JARs, `.class`, selected binaries, by strings
- A constant defined in another file of the same tree

## Out of scope
- Obfuscated or packed code
- A value that exists only at deploy time
- One recall number that blends source and artifact

## Scores
Source and artifact are separate. A source recall does not describe artifact coverage, and the reverse is not true.

## Provenance
Each finding says source, config, or artifact. If it does not, the scan is not a 2.0 scan.
