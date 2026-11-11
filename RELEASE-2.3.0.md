# QCI Crypto Inventory 2.3.0

2.3.0 is an artifact release. Source scanning is unchanged.

## What it reads

| Artifact | Reported |
|----------|----------|
| `.class` constant pool | Class, method, algorithm, parameter |
| JAR, and a JAR inside a WAR or EAR | The same, with the archive in the path |
| Wheel | A native library inside it |
| Image tarball | Certs, configs, and class files inside it |
| ELF | The libraries it links (`DT_NEEDED`) |
| PE | The DLLs it imports |
| `.so`, `.dll`, `.dylib` on disk | OpenSSL or BouncyCastle, by name |

## What it does not

- A runtime tracer, network traffic, or an endpoint agent.
- Packed or obfuscated code.
- A Go binary that statically links its crypto. There is no `DT_NEEDED` entry to read.
- One recall number. Source and artifact stay separate.

## Corpus

`tests/fixtures/artifacts/expected.json`: 6 expected findings, 2 negatives. CI runs it. This number is not the source recall.
