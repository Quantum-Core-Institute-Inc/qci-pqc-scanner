# qci-pqc-scan 2.2.0

2.2 adds languages and infrastructure declarations. It is not a new detection class.

The product is a crypto inventory of source, config, and artifacts. It exports a CycloneDX 1.6 CBOM. It is not a complete bill of materials.

## What changed

- **C#.** `RSA.Create`, `ECDsa.Create`, `Aes.Create`, `SHA256.Create`.
- **Rust.** `RsaPrivateKey`, P-256, `Aes256Gcm`, Ed25519.
- **Terraform.** `aws_kms_key`, ACM certificates, a TLS minimum version.
- **CloudFormation.** `AWS::CertificateManager::Certificate`, `KeyAlgorithm: RSA`.
- **Dependency graph.** Written to `graph.json` and shown in the HTML report: app, library, finding, path.
- **Name.** The product is a crypto inventory. `cbom.json` is the file format.

## Also in this line, since 2.1

- Purls on dependency findings.
- Owner, system, and data lifetime from the metadata file.
- Crypto-agility inferred from provenance: config or code.
- Certificate chain length and named extensions.
- Key protector recorded from the file: file, KMS, or HSM. The scanner does not call either.

## Not in 2.2

- Live traffic and negotiated cipher suites
- Defect CWEs
- IANA registry identifiers as forms
- Cisco, MikroTik, F5, OPC UA, SPIRE
- Envoy and PostgreSQL config lines (open, not in this tag)

## Upgrade

`pip install` the 2.2.0 tag. A 2.1 baseline still loads. Artifact findings are not regressions.

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) and [docs/OPERATOR.md](docs/OPERATOR.md).
