# How a finding is made

This page is for a reviewer. It says what the scanner reads, how a name becomes a finding, and what it writes. It does not say how a finding is scored. That is the benchmark.

## What is read

The scanner reads files. It does not read connections.

| Surface | What |
|---------|------|
| Source | Python, Java, Go, C, C#, JavaScript, TypeScript, Rust, Kotlin. |
| Configuration | `.conf`, `.cnf`, `.yaml`, `.json`, `.properties`, and extensionless names such as `sshd_config`. |
| Artifacts | JARs, class files, wheels, ELF binaries, PE imports, minified JavaScript. |
| Dependencies | Manifests and lockfiles. The library name and, where the file states it, the version. |

A symlink that leaves the scan root is not followed. A file the scanner cannot read is listed in the coverage file with the reason.

## How a name becomes a finding

Three checks. All three must pass.

1. **A pattern matches.** The line names an algorithm, a library, or a protocol. `rsa.generate_private_key`, `getInstance("AES")`, `HostKeyAlgorithms ssh-rsa`.
2. **A context check passes.** A name inside a string does not count unless the string is passed to a crypto API, or the line is a declaration (`algorithm:`, an assignment, an enum constructor). A name in a comment does not count.
3. **A parameter is read, if one is there.** From the matched statement, from a name the file defines once, from a constant in another file, or from a later call on the object the line creates. Two candidate values mean no answer. A blank parameter is better than a wrong one.

A constant that resolves to an algorithm is a use. `KEY_ALG = "DSA"` then `return KEY_ALG` is a DSA finding.

## What is written

| File | What it is |
|------|------------|
| `report.html` | The report a reviewer should open. Findings, the role summary, coverage, recommendations. |
| `cbom.json` | A CycloneDX 1.6 CBOM. Algorithms, certificates, related material, protocols. |
| `findings.sarif` | SARIF, for a tool that reads it. |
| `scan-coverage.json` | Every file skipped, and why. |
| `policy-result.json` | Present only when a policy was supplied. |

The role summary states key establishment and signatures, and says when the two roles differ.

## What is not claimed

The scanner does not score itself. A recall number, a precision number, and a ticket-ready number come from the [CBOM Benchmark](https://github.com/Quantum-Core-Institute-Inc/CBOM-Benchmark), which runs the scanner on a labeled corpus and scores the CBOM.

What the scanner does not do is in [LIMITATIONS.md](LIMITATIONS.md). The short version: it reads files, not the wire, and a name assembled at runtime is out of scope.
