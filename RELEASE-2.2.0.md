# qci-pqc-scan 2.2.0

2.2 adds languages and declarations. It is not a new detection class.

## What changed

- C# and Rust calls: RSA, ECDSA, AES, SHA-256, Ed25519.
- Terraform and CloudFormation: KMS keys, ACM certificates, TLS minimum version.
- The dependency graph is written to `graph.json` and shown in the HTML report.
- The product is named a crypto inventory. The file remains a CycloneDX CBOM.

## Not in 2.2

- Live traffic
- Defect CWEs
- IANA registry identifiers as forms
- Cisco, MikroTik, F5, OPC UA, SPIRE

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
