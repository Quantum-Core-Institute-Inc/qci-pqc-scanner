# NIST-Aligned PQC Migration Guide

Short, practical guide for teams using the QCI PQC scanner.  
Aligned with **NIST IR 8547** (Transition to Post-Quantum Cryptography Standards, final October 2026), **FIPS 203/204/205**, and **CSWP 39** (Crypto Agility).

> This is a summary for operational use. Always consult the official NIST publications for authoritative language.

## 1. What is quantum-vulnerable?

Shor’s algorithm breaks the public-key algorithms used for key establishment and digital signatures:

| Current (quantum-vulnerable) | Primary NIST replacement | Standard |
|------------------------------|---------------------------|----------|
| RSA key transport / OAEP | ML-KEM | FIPS 203 |
| DH / ECDH | ML-KEM | FIPS 203 |
| RSA signatures | ML-DSA (general) or SLH-DSA (conservative) | FIPS 204 / 205 |
| ECDSA / EdDSA | ML-DSA or SLH-DSA | FIPS 204 / 205 |

Symmetric algorithms (AES-256, SHA-256/SHA-3, etc.) remain safe with appropriate key lengths. Focus migration effort on public-key cryptography first.

## 2. Timeline (NIST IR 8547 + federal policy)

| Milestone | Date | Applies to |
|-----------|------|------------|
| Quantum-vulnerable public-key algorithms **deprecated** | After 2030 | General NIST guidance |
| Quantum-vulnerable public-key algorithms **disallowed** | After 2035 | General NIST guidance |
| PQC key establishment required | 31 Dec 2030 | Federal high-value / high-impact / highly sensitive systems (EO 14412 / OMB M-26-15) |
| PQC digital signatures required | 31 Dec 2031 | Same federal systems |

2035 is **not** the only date that matters. High-value and long-lived data should move earlier because of harvest-now-decrypt-later risk.

## 3. Detailed migration steps

### Phase 0 — Governance and scope
- Assign an owner for the cryptographic inventory and the migration program.
- Define scope: source code, libraries, certificates, TLS/SSH configs, hardware security modules, third-party services.
- Decide risk appetite for harvest-now-decrypt-later data (data that must stay confidential beyond 2030–2035).
- Reference: NIST IR 8547, CSWP 39, NCCoE Migration to PQC project.

### Phase 1 — Discovery and inventory
1. Run this scanner on all in-scope repositories:
   ```bash
   PYTHONPATH=src python -m qci_pqc.cli scan /path --adapter "internal,semgrep" --out reports
   ```
2. Produce and store the CycloneDX CBOM (`cbom.json`) as the baseline cryptographic bill of materials.
3. Supplement with dependency scanning, certificate inventory, and TLS/SSH configuration review.
4. Tag each finding with:
   - System / service owner
   - Data lifetime (how long the data must remain confidential)
   - Exposure (internal only vs. internet-facing)
   - Current algorithm and key size

### Phase 2 — Risk prioritization
Rank findings using these factors (highest first):
1. Long-lived or high-value data protected by quantum-vulnerable key establishment (harvest-now-decrypt-later).
2. Internet-facing or partner-facing interfaces.
3. Root CAs, code-signing, and firmware-signing keys.
4. Systems subject to federal accelerated timelines (high-value / high-impact).
5. Everything else.

Document a prioritized backlog with target migration windows.

### Phase 3 — Algorithm and library selection
| Use case | Preferred algorithm | Notes |
|----------|---------------------|-------|
| Key establishment / KEM | ML-KEM-768 (FIPS 203) | Default for most applications |
| General signatures | ML-DSA-65 (FIPS 204) | Good size/performance balance |
| Long-term / root / firmware signatures | SLH-DSA (FIPS 205) | Larger signatures; lattice-independent |
| Constrained signatures (later) | FN-DSA (FIPS 206 draft) | Wait for final standard if size is critical |
| Transition period | Hybrids (X25519+ML-KEM, ECDSA+ML-DSA) | Maintain classical security while adding PQC |

Prefer libraries that implement the final FIPS standards (not pre-standard Kyber/Dilithium) or that clearly document their FIPS compliance path.

### Phase 4 — Design and crypto-agility
- Isolate cryptographic calls behind a small internal API or configuration so the algorithm can be changed without rewriting business logic (CSWP 39).
- Plan for larger key, ciphertext, and signature sizes.
- Decide hybrid vs. pure-PQC per protocol and counterpart readiness.
- Update threat models and security architecture documents.

### Phase 5 — Implementation and testing
1. Introduce PQC or hybrid support in a non-production branch.
2. Update unit and integration tests; add the new forms to the golden corpus if they are project-specific.
3. Test interoperability with partners and with both classical-only and PQC-capable peers.
4. Validate performance (especially signature size and verification speed for SLH-DSA).
5. Re-scan and confirm the targeted vulnerable findings are reduced or marked as migrated.

### Phase 6 — Deployment and cutover
- Deploy in stages (internal → partners → public).
- Monitor for failures caused by size limits, older clients, or HSM constraints.
- Keep classical algorithms available only where still required for interoperability, and document the exception.
- Update the CBOM and re-run the scanner after each major deployment.

### Phase 7 — Retirement and ongoing agility
- Remove pure classical public-key algorithms according to the IR 8547 timeline (deprecated after 2030, disallowed after 2035) and any earlier organizational or federal deadlines.
- Establish a recurring review (at least annually) of the cryptographic inventory.
- Treat the next algorithm change as a planned exercise of crypto-agility rather than an emergency project.
- Keep the scanner and golden corpus in CI so new vulnerable introductions are caught early.

## 4. Recommended migration order (summary)

1. **Inventory** — Know what you have (this scanner + CBOM).
2. **Prioritize** — Long-lived data, high-value assets, external interfaces, root CAs, firmware signing.
3. **Key establishment first** — Move to **ML-KEM** (prefer ML-KEM-768 as the default).
4. **Signatures next** — **ML-DSA** for general use; **SLH-DSA** where lattice-independence or long-term assurance matters more than size.
5. **Use hybrids during transition** — X25519+ML-KEM, ECDSA+ML-DSA, etc., while both ends are upgraded.
6. **Retire** — Remove pure classical public-key algorithms according to the timeline above.
7. **Build crypto-agility** — Treat this migration as the first exercise of ongoing agility (CSWP 39), not a one-time project.

## 4. Parameter-set starting points

| Algorithm | Recommended starting point | Notes |
|-----------|----------------------------|-------|
| ML-KEM | ML-KEM-768 | NIST default for most uses |
| ML-DSA | ML-DSA-65 | Good balance of size and security |
| SLH-DSA | SLH-DSA-SHA2-128f or equivalent | Larger signatures; use where conservatism is required |
| FN-DSA (Falcon) | Wait for final FIPS 206 | Compact signatures; still in standardization |

## 5. Practical steps for a codebase

1. Run this scanner (`--adapter internal,semgrep` or others) and review the HTML report + CBOM.
2. Tag every Shor-vulnerable finding with an owner and a target migration window.
3. Prefer libraries that already implement FIPS 203/204/205 (or are on a clear path).
4. Introduce hybrid constructions where protocol or interoperability constraints exist.
5. Update tests, CI gates (`--fail-on vulnerable`), and documentation.
6. Re-scan after each change; use the golden corpus to avoid regressions.

## 6. Key references

- [NIST IR 8547](https://doi.org/10.6028/NIST.IR.8547) — Transition to Post-Quantum Cryptography Standards (Oct 2026)
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) — SLH-DSA
- [CSWP 39](https://csrc.nist.gov/pubs/cswp/39/final) — Considerations for Achieving Crypto Agility
- NCCoE Migration to PQC project — practical guidance and use cases

## 7. Disclaimer

This guide is a condensed operational summary. It does not replace NIST publications, organizational risk assessments, or legal/compliance advice. Timelines and requirements can differ for federal systems, regulated industries, and long-lived data.
