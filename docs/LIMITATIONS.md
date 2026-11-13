# Limitations

The 1.0 page is retired. This is the ceiling.

## In scope
- Source and configuration, as in 1.x
- Compiled artifacts: JCA calls in `.class` bytecode (algorithm, key size, curve, mode), JARs, WARs, wheels, image tarballs, ELF `DT_NEEDED`, PE imports, native libraries by name
- Minified JavaScript bundles, including those under `dist/`, `build/` and `target/`
- ELF binaries: functions imported from a crypto library (OpenSSL, libsodium), algorithm names handed to OpenSSL's fetch-by-name APIs, and crypto functions linked into a Go binary. Key size, curve and HMAC hash are read from the call site on x86-64 only
- A constant defined in another file of the same tree

## Out of scope
- Obfuscated or packed code
- A value that exists only at deploy time
- Native binaries that link their crypto statically with symbols stripped, or reach it through another library (a program that uses libcurl, not libcrypto, imports nothing from OpenSSL)
- Mach-O and PE binaries beyond their import tables; call-site parameters on architectures other than x86-64
- In a Go binary that links `crypto/tls`: the algorithms TLS itself brings in. They show the program speaks TLS, not what it chose
- One recall number that blends source and artifact

## Scores
Source and artifact are separate. A source recall does not describe artifact coverage, and the reverse is not true.

## Provenance
Each finding says source, config, or artifact. If it does not, the scan is not a current scan.
