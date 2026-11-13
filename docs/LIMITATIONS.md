# Limitations

The 1.0 page is retired. This is the ceiling.

## In scope
- Source and configuration, as in 1.x
- Compiled artifacts: JCA calls in `.class` bytecode (algorithm, key size, curve, mode), JARs, WARs, wheels, image tarballs, ELF `DT_NEEDED`, PE imports, native libraries by name
- Minified JavaScript bundles, including those under `dist/`, `build/` and `target/`
- A constant defined in another file of the same tree

## Out of scope
- Obfuscated or packed code
- A value that exists only at deploy time
- One recall number that blends source and artifact

## Scores
Source and artifact are separate. A source recall does not describe artifact coverage, and the reverse is not true.

## Provenance
Each finding says source, config, or artifact. If it does not, the scan is not a current scan.
