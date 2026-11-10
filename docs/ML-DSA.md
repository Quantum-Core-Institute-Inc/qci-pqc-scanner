# ML-DSA (FIPS 204) — Post-Quantum Digital Signatures

**ML-DSA** (Module-Lattice-Based Digital Signature Algorithm) is NIST’s primary standard for post-quantum digital signatures.  
Finalized as **FIPS 204** on 13 August 2024. Derived from CRYSTALS-Dilithium.

## What it does
- Produces a digital signature over a message.
- Provides authenticity, integrity, and non-repudiation.
- Secure against both classical and quantum attackers (based on Module-LWE / Module-SIS lattice problems).
- Replaces RSA signatures, ECDSA, and EdDSA for long-term use.

## Parameter sets (FIPS 204)

| Parameter set | NIST category | Public key | Private key | Signature | Typical use |
|---------------|---------------|------------|-------------|-----------|-------------|
| **ML-DSA-44** | 2 | 1,312 B | 2,560 B | 2,420 B | Size-sensitive, shorter-lived |
| **ML-DSA-65** | 3 | 1,952 B | 4,032 B | 3,309 B | **Common general-purpose default** |
| **ML-DSA-87** | 5 | 2,592 B | 4,896 B | 4,627 B | High assurance; required by CNSA 2.0 for U.S. national security systems |

Compared with classical signatures:
- Ed25519 / ECDSA P-256 signature ≈ 64 bytes
- ML-DSA-65 signature ≈ 3,309 bytes (~50× larger)

Performance is generally acceptable for most applications; the main impact is size (certificates, TLS handshakes, blockchains, constrained devices).

## ML-DSA vs Dilithium
- ML-DSA is the standardized name and specification.
- It is derived from CRYSTALS-Dilithium but is **not** bit-compatible with pre-standard Dilithium implementations.
- Use libraries that implement **FIPS 204** (not old competition code).

## Modes
- **Pure ML-DSA** — signs the message directly.
- **HashML-DSA** — pre-hashes the message (useful for large messages). The hash must provide sufficient security strength relative to the parameter set.
- Signing can be deterministic or hedged (randomized); hedged is often preferred for side-channel resistance.

## When to use ML-DSA
- General-purpose signatures: code signing, certificates, documents, authentication, JWTs, etc.
- Prefer **ML-DSA-65** unless you have a specific reason to choose another set.
- Use **ML-DSA-87** when higher assurance or CNSA 2.0 compliance is required.
- Use **SLH-DSA** (FIPS 205) instead when you want a signature whose security rests only on hash functions (larger signatures, no lattice assumptions).

## Migration notes
- Pair with **ML-KEM** (FIPS 203) for key establishment.
- Hybrids (e.g. ECDSA + ML-DSA) are common during transition.
- Plan for larger keys and signatures in protocols, certificates, and storage.
- Federal high-value systems: PQC signatures by 31 Dec 2031 (EO 14412 / OMB M-26-15).
- General NIST guidance (IR 8547): quantum-vulnerable signatures deprecated after 2030, disallowed after 2035.

## Official reference
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — Module-Lattice-Based Digital Signature Standard
- [NIST IR 8547](https://doi.org/10.6028/NIST.IR.8547) — Transition guidance
