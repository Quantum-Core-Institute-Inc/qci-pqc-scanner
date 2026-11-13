# QCI Crypto Inventory 2.3.4.4

TLS cipher suites are reported one by one.

- Each suite a configuration names is a finding under its IANA name, whether the file wrote that or the OpenSSL spelling (`DES-CBC3-SHA`).
- Protocol versions are read from Apache, HAProxy, Spring, Go, OpenSSL, Python and .NET as well as nginx.
- Suites and versions are CycloneDX protocol assets in the CBOM, not algorithms.
- A suite or version a directive turns off (`-TLSv1`, `!RC4-SHA`) is not reported. In source code, a suite name in a log line, an unused string or somebody's own enum is not reported.
