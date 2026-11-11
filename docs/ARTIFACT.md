# Artifact score

This number is not the source recall.

## What an artifact finding comes from

| Source | How |
|--------|-----|
| `.class` | Constant pool. Class, method, algorithm, parameter. |
| JAR, WAR, EAR | A zip of those. A JAR inside a WAR is opened. |
| Wheel | A zip. A native library inside it. |
| Image tarball | Certs, configs, and class files inside it. |
| ELF | `DT_NEEDED`. The libraries it links. |
| PE | The import directory. The DLLs it loads. |
| `.so`, `.dll`, `.dylib` | By name. `libcrypto` is OpenSSL. `libsslfoo` is not. |

## What it does not

- A string scan of the whole binary.
- Packed or obfuscated code.
- A Go binary that statically links its crypto.
- A runtime tracer or network traffic.

## The number

| Field | Meaning |
|-------|---------|
| count | Artifact findings |
| named_class | The snippet names the class |
| with_parameter | Mode, hash, or version is set |

`tests/fixtures/artifacts/expected.json` is the corpus. Six expected findings, two negatives. CI runs it.
