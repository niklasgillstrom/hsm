# Example fixtures — real HSM attestations

This directory contains real attestation fixtures produced by the reference hardware. Each fixture is the input/output pair for a single successful HSM-attestation verification:

| Vendor | Hardware | Serial |
|--------|----------|--------|
| YubiHSM 2 | Yubico YubiHSM 2 | 20783176 |
| Securosys Primus | Primus HSM (RSA 4096) | 18386101 |

These fixtures back the integration tests in `src/test/java/eu/gillstrom/hsm/integration/RealAttestationFixtureTest.java`. They make the verifier's behaviour reproducible end-to-end against real attestation data, not just against the synthetic `TestPki`-based negative paths.

## What is in each fixture

Each subdirectory contains exactly two files:

- **`request.json`** — the HSM-attestation portion of an `/api/v1/attestation/verify` request body. Contains:
  - `csr` — a real PKCS#10 CSR signed by the HSM-held private key for the attested key.
  - `attestationCertChain` — real attestation chain leading to the pinned vendor root CA.
  - For Securosys only: `attestationData` (XML, base64-encoded), `attestationSignature` (base64).
- **`expected.json`** — the HSM-attestation-relevant fields from the verification response. Contains `valid`, fingerprints, vendor, model, serial, `keyOrigin`, `keyExportable`, etc.

## Provenance and confidentiality

These fixtures are produced exclusively from operator-controlled hardware and operator-controlled identifiers. **No third-party customer information is present:**

- **HSM serial numbers** (20783176 for Yubico, 18386101 for Securosys) — physical devices in the reference setup. They appear in attestation cert subjects and are not cryptographic secrets.
- **CSR Subject DN** (`C=SE, O=5569743098, CN=1231015932`) — operator-controlled organisation number and Swish number. Both are public-register data (Bolagsverket and Swish marketplace).
- **Attested public keys, attestation chains, and signatures** — kept in raw production form. They are public by design (attestation evidence is publicly verifiable per `THREAT_MODEL.md` § Information disclosure).

Customer-flow fields that are not needed for HSM-attestation verification — `bankIdSignatureResponse`, `bankIdOcspResponse`, signatory name — are not included in these example fixtures.

No private keys or BankID-derived secrets exist anywhere in this directory.

## Reproducibility contract

The reproducibility a peer reviewer can claim from these fixtures is **asymmetric**:

| Claim | Reproducible? | How |
|-------|---------------|-----|
| The pinned vendor root validates this chain | Yes | `mvn -B test` runs `RealAttestationFixtureTest` against the embedded vendor roots |
| The CSR public key matches the attested key | Yes | The integration test asserts `publicKeyMatch == true` |
| Attested key was generated on-device, non-exportable | Yes | The test asserts `keyOrigin == "generated"` and `keyExportable == false` |
| A different CSR for the same attestation is rejected | Yes | The negative test substitutes a synthetic key pair and asserts rejection |
| The CSR proves possession of the attested key *(1.7.0)* | Yes | `*FixtureCsrPassesProofOfPossession`: the CSR's own signature verifies under its key (the check `AttestationService` applies, mirrored in the test because the method is private), a one-bit flip of the signature fails it, and the fixture passes through `AttestationService.verify` |
| The chain is refused under another root with the same subject name *(1.7.0)* | Yes | `*FixtureIsRejectedUnderADifferentPinnedRoot`: a substitute root with the real root's subject name and another key; `chainValid` and `valid` are false |
| An unknown vendor token is refused *(1.7.0)* | Yes | `*FixtureWithAnUnknownVendorTokenIsRefusedByTheVendorRouter`: the same evidence under tokens such as `acme`, `YubiHSM 2` or `Primus HSM` |
| Firmware and FIPS state *(1.7.0)* | Yes | `yubicoFixtureReportsFirmwareAndFipsIndicatorButNoFipsApprovedFlag`: firmware `2.2.0`, FIPS indicator 5, no FIPS-approved flag (`41482.4.12`); `securosysFixtureReportsNoFirmwareOrFipsFields`: none of the three; `requiringFipsApprovedModeRefusesBothRealFixtures`: with `swish.key-policy.require-fips-approved-mode=true` both are refused. `expected.json` predates these fields and does not list them |
| The reviewer can generate a *new* attestation | **No** | Requires physical HSM and vendor-specific signing flow. See `PEER_REVIEW_GUIDE.md` |

This asymmetry is intrinsic to hardware-attestation verification: the verifier's behaviour is reproducible from any attested input, but generating a fresh attested input requires the hardware that produced it. A reviewer can be convinced of the verifier's correctness without owning hardware, by relying on:

1. **The pinned root CA's authenticity** — the Securosys and Yubico roots are real vendor-issued CAs. Their SHA-256 fingerprints are documented in the "Pinned trust anchor" comment blocks in `YubicoVerifier.java` and `SecurosysVerifier.java`, listed in `README.md` ("Production") and asserted by `TrustAnchorPinningTest`. A reviewer can re-verify the Yubico root against `https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem` and, since 1.7.0, the Securosys root against the source its block records (`https://support.securosys.com/external/knowledge-base/article/147`, file `hsm_rsa_root.crt`); neither file has been byte-compared with the constant in this repository, but the real attestations here validate under both roots, so the constants are the roots the reference devices chain to. A deployer who replaces either root (`swish.trust-anchors.yubico` / `securosys`) with a different one makes these fixtures fail to verify, as `TrustAnchorsTest` shows with a test root.
2. **The CSR-binding determinism** — `MessageDigest.isEqual` on public-key encodings rejects any substitution. The CSR-mismatch negative test demonstrates this.

## Regenerating the fixtures

If you have the original captured request/response JSON pairs (i.e., complete `/api/v1/attestation/verify` exchanges), you can regenerate the trimmed fixtures with:

```bash
python3 scripts/trim-fixtures.py path/to/captured/ examples/
```

(Trim script not bundled — generation was done one-shot from the captured payloads listed in the table above.)
