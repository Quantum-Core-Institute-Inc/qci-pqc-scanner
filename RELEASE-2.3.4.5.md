# QCI Crypto Inventory 2.3.4.5

Compiled and minified code is read instead of skipped. 2.3.4.4 (TLS cipher suites reported one by one) was never tagged, so this release carries its changes too.

- **Minified JavaScript.** A bundle is split back into statements and short aliases are followed to the crypto call they stand for. `dist/` and other build-output directories are scanned unless the source they were built from is in the same tree.
- **Compiled Java.** `.class` files and the classes inside `.jar`, `.war` and `.ear` archives are parsed, and the algorithm string passed to each JCA call (`Cipher.getInstance`, `MessageDigest.getInstance`, `KeyPairGenerator.getInstance` and the rest) is reported.
- **Native binaries.** ELF binaries are read for the crypto functions they import, the algorithm names they fetch by string, the Go crypto packages compiled into them, and key sizes passed as constants at the call site. Raw byte matches are not findings: "DH" somewhere in a binary is not Diffie-Hellman.
- **TLS cipher suites.** Each suite a configuration names is a finding under its IANA name, whether the file wrote that or the OpenSSL spelling (`DES-CBC3-SHA`). Protocol versions are read from Apache, HAProxy, Spring, Go, OpenSSL, Python and .NET as well as nginx. Both are CycloneDX protocol assets in the CBOM.
- **Fewer false matches.** Base64 inside a PEM block is no longer searched for algorithm names.

Not measured in a benchmark release yet. The published figures are still those of 2.3.4.3.
