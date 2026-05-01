# Peer-review guide — hsm

This document is written for a peer reviewer of Article 1 (Gillström, in preparation; target venue: *Capital Markets Law Journal*) and Article 2 (Gillström, in preparation; target venue: *Computer Law & Security Review*) who wants to reproduce the central verification claims these articles make. Companion repos `gatekeeper/` and `railgate/` complete the **triadic system** (since v1.2.0) described in Article 1 §4.2 and Article 2 §9.3:

- **hsm** (this repo) carries the verifier core and the BankID-based certificate-issuance flow that surrounds it.
- **gatekeeper** is the NCA-facing supervisory API shell that wraps those verifiers for regulatory use, and from v1.1.0 also exposes the settlement-time signature verification endpoint that railgate consumes.
- **railgate** is the central-bank settlement-rail enforcement layer that calls gatekeeper's verification endpoint at settlement time (RIX-INST in Sweden; generalisable to TIPS, FedNow, FPS, NPP).

The three components together operationalise the data-minimised quadruple-triangulation model: only digest, signature, and certificate identifiers traverse the supervisor boundary — no transaction payload content is exposed at any layer.

## Version 1.2.0 — what's new for hsm reviewers

hsm itself has **no code changes** in v1.2.0 relative to v1.0.0. The version bump aligns hsm with the gatekeeper and railgate companion artefacts so the trio carries a uniform version number, and ships updated cross-references (`CROSS_REFERENCE.md`) plus this peer-review-guide section so reviewers can navigate the triadic system from any of the three repositories. The verifier core and the BankID-issuance flow in this repo are unchanged and reviewers' reproducible-assertion notes from v1.0.0 still apply unchanged.

---

## What this repo is / isn't

**Is:**

- A **reference implementation** of the HSM attestation verification procedure described in Article 1 §§4.1–4.2. Four vendor-specific verifiers (Securosys, Yubico, Azure Managed HSM, Google Cloud HSM) plug into a common `HsmAttestationVerifier` interface. Each anchors a PKIX `CertPathValidator` at a pinned vendor root CA.
- A **demonstrator** of the end-to-end certificate-issuance flow: a CSR + attestation evidence → `AttestationService.issueCertificate()` → BankID-authenticated signatory → pluggable signatory-rights check → `SwishCaService.issue()`.
- **Deterministically reproducible**. The PKIX-based test suite builds a throwaway CA with `TestPki` and asserts that non-pinned chains are rejected — no network, no mocks, no vendor hardware required.
- **MIT-licensed**.

**Isn't:**

- Production code. The Marvell TLV blob parser for Azure/Google is speculative; the `SignatoryRightsVerifier` default is `fail-closed` (intentional); the BankID XML-DSig trust anchor list is a placeholder.
- An eIDAS Qualified Trust Service. Certificate issuance here is reference-quality, not a QTSP.
- A complete production HSM integration. The HSM-side configuration, audit pipeline, and operational infrastructure that the Swish case study runs on are documented in `HARDWARE_BASELINE.md` (separate document, sibling to this repo).

**What is pinned.** Each verifier embeds a single trust anchor as a Java text-block constant in the verifier source (e.g., `private static final String YUBICO_ROOT_CA = """ ... """;` for the Yubico verifier; `private static final String ATTESTATION_TRUST_ANCHOR = """ ... """;` for the Azure and Google Cloud HSM verifiers) and parses it in the constructor. A load failure is fatal: the constructor throws `IllegalStateException` and Spring Boot refuses to start. Classpath resources under `src/main/resources/` are limited to `application.yaml`; the trust anchors do not live there.

**Real vendor-issued roots** are embedded for the Securosys Primus path and the Yubico YubiHSM path. The Yubico root is sourced from `https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem`; SHA-256 fingerprint `09:4A:3A:C4:...:39:2F:B7:24` documented inline above the PEM constant in `YubicoVerifier.java`.

**What is placeholder.**

- **Gatekeeper client default is fail-closed.** `swish.gatekeeper.mode=fail-closed` is the default; `FailClosedGatekeeperClient` throws `GatekeeperException` on every call. This is the production-safe default — it forces a deployer to consciously wire `swish.gatekeeper.mode=http` and `swish.gatekeeper.url` against an authoritative NCA endpoint before any signing certificate can be issued. The `mock` mode is for demonstration and CI only; it auto-registers an ephemeral RSA key in the local `GatekeeperKeyRegistry` and emits a startup `WARN` log so the non-authoritative posture cannot be missed.
- **Cloud-HSM attestation trust anchor (rotation-due, owner-chain not implemented).** `AzureHsmVerifier` and `GoogleCloudHsmVerifier` pin the constant `ATTESTATION_TRUST_ANCHOR`, which is the genuine Marvell/Cavium LiquidSecurity Root CA fetched from Marvell's official distribution (`marvell.com/.../liquid_security_certificate.zip`, the same anchor referenced by Google Cloud HSM's open-source verification code). SHA-256 `97:57:57:F0:D7:66:40:E0:3D:14:76:0F:8F:C9:E3:A5:58:26:FA:78:07:B2:C3:92:F7:80:1A:95:BD:69:CC:28`. The bundled cert expired on 2025-11-16; deployers should fetch the current cert from Marvell, verify its fingerprint, and replace the constant before relying on chain validation for attestations created after the expiry. PKIX does not check the trust anchor's own validity period, so the structural rejection-path tests still pass with the bundled (expired) anchor. **Dual-chain not implemented:** Google Cloud HSM's published Python sample (`verify_chains.py`, copyright 2021) verifies attestations against two parallel chains — the Marvell manufacturer chain (bundled here) AND Google's "Hawksbill Root v1 prod" owner chain (not bundled). Azure Managed HSM is expected to follow an analogous pattern with a Microsoft-controlled owner root. This verifier implements only the manufacturer chain; production deployment of either cloud path requires adding owner-chain validation per current cloud-vendor documentation. The Yubico and Securosys roots are non-expiring real vendor-issued roots and the corresponding paths are production-trustable once the rest of the supervisory configuration (gatekeeper URL, signatory-rights adapter, BankID anchors) is in place.
- **`SignatoryRightsVerifier` default** — `FailClosedSignatoryRightsVerifier` returns UNKNOWN on every call and emits a `WARN` log. The `MockAgreementRegistrySignatoryRightsVerifier` reads a JSON file. Neither is a Swish or Bolagsverket adapter.
- **Marvell TLV parser** — assumes the signature is the last N bytes of the attestation blob. Sufficient for shape-testing, not for production trust.

---

## Reproducibility contract

A reviewer can independently reproduce different layers of the supervisory flow depending on which fixtures and which gatekeeper they have access to.

| Layer | What runs without external infrastructure | What requires a deployed NCA gatekeeper |
| ----- | ------------------------------------------ | ---------------------------------------- |
| Local verification (Phase 1) | `mvn -B test` — all 16 synthetic fail-closed tests run without network or HSM. | Nothing additional. |
| Gatekeeper verify + confirm (Phases 2 + 4) | `GatekeeperFlowTest` runs against `MockGatekeeperClient`, an in-process gatekeeper that signs receipts with an ephemeral RSA key registered in the local trust store. The byte-identity of the canonical receipt is locked by `WireFormatGoldenBytesTest` — any drift between this repo's canonicalizer and the gatekeeper repo's canonicalizer breaks the assertion in **both** repos at the same time. | An end-to-end test against a live `gatekeeper` instance (with mTLS configured, an issuer-CA bundle for Step 7, and `gatekeeper.signing.mode=configured` against a real seal certificate) requires deploying the gatekeeper — see `gatekeeper/PEER_REVIEW_GUIDE.md`. |
| Real attestation evidence | `RealAttestationFixtureTest` exercises real Yubico and Securosys fixtures against the pinned vendor roots. No HSM hardware required at test-run time; the fixtures were captured at the originating site. | Fresh HSM hardware is only required to capture **new** fixtures. |
| Cross-repo byte-format compatibility | `WireFormatGoldenBytesTest` in this repo asserts a hardcoded golden string. The same string is asserted in the gatekeeper repo's `WireFormatGoldenBytesTest`. Any deviation fails both tests. | Nothing additional. |

The mock gatekeeper deliberately produces real cryptographic signatures (RSA-3072, `SHA256withRSA`) that the local `ReceiptVerifier` validates with the same code path that production HTTP gatekeeper traffic uses. The only thing the mock loses relative to a real NCA gatekeeper is the legal weight of the seal — the cryptographic shape is identical, which is what makes the supervisory flow falsifiable in this repo's test harness alone.

---

## Requirements

- **Java 21** (toolchain configured in `pom.xml`).
- **Maven ≥ 3.6.3** (enforced at build time by `maven-enforcer-plugin`; this matches Spring Boot 4.x's own Maven floor and OWASP Dependency-Check 12.x's requirement). Tested on Maven 3.9.15.
- **BouncyCastle** (pulled in via Maven; no system installation required).
- **Internet-less sandbox is fine.** All tests build their PKI in memory from `TestPki`; no network calls.
- No HSM hardware required to run the test suite.

---

## Build and test

```bash
cd hsm
mvn -B test
```

Expected result: **BUILD SUCCESS** with all tests green.

Test count at submission time: **26 tests across 9 test classes**, split into four layers:

- **16 synthetic fail-closed tests** across 7 classes under `eu.gillstrom.hsm.{verification,service}` — these build throwaway PKIs in memory with `TestPki` and assert that the verifier rejects every chain that does not anchor at the pinned vendor root. They prove the *structural* fail-closed contract.
- **4 real-data integration tests** in `eu.gillstrom.hsm.integration.RealAttestationFixtureTest` — these run real attestation fixtures produced by the reference Yubico YubiHSM 2 (serial 20783176) and Securosys Primus (serial 18386101) hardware against the pinned (real) Yubico and Securosys roots. They prove the *operative* contract: a real attestation passes when correctly bound to its CSR, and is rejected when the CSR public key is substituted. Fixtures live under `examples/<vendor>/`; if absent, those tests skip cleanly via `@EnabledIf`. See `examples/README.md` for fixture provenance and the asymmetric reproducibility model.
- **3 supervisory-loop tests** in `eu.gillstrom.hsm.integration.GatekeeperFlowTest` — exercise the four-phase flow against the in-process `MockGatekeeperClient`: a successful Phase 1–4 round-trip with `loopClosed=true` and `publicKeyMatch=true`, a tampered-signature rejection at the `ReceiptVerifier` boundary, and a byte-identity assertion of the canonical receipt format against a hardcoded golden string.
- **3 cross-repo wire-format tests** in `eu.gillstrom.hsm.gatekeeper.WireFormatGoldenBytesTest` — lock the canonical wire format to a literal that is shared byte-for-byte with the gatekeeper repository's `WireFormatGoldenBytesTest`. Any future change to field ordering, separator, escape rules, or version marker that breaks byte-identity between the two repos breaks this assertion immediately on both sides.

The rationale for each fail-closed and integration test is documented inline in the respective test file's Javadoc.

### The four-phase supervisory flow

`AttestationService.verifyAndIssue(...)` orchestrates the four phases described in `README.md` "Four-phase supervisory issuance flow":

1. **Local verification** — pinned-root PKIX, BankID XML-DSig + OCSP, signatory rights.
2. **Gatekeeper verify** — `GatekeeperClient.verify(VerifyRequest)` produces an `VerifyResponse` whose canonical bytes are signed by the operating NCA gatekeeper. `ReceiptVerifier` checks the signature against `GatekeeperKeyRegistry`.
3. **Issuance** — `IssuanceClient.issue(...)` produces the certificate, recording `verifyReceiptId` so the certificate is bound back to the gatekeeper-approved attestation.
4. **Gatekeeper confirm** — `GatekeeperClient.confirm(IssuanceConfirmRequest)` closes the supervisory loop. Anomalies — public-key mismatch, certificate not chaining to a trusted issuer CA, unknown verification ID — are surfaced in the `IssuanceConfirmResponse.registryStatus` enum.

`Stage` is an enum on `IssuanceResponse` that records the precise phase at which the flow stopped, including the anomalous post-issuance state `ISSUED_BUT_GATEKEEPER_CONFIRM_FAILED` (a certificate exists but supervisory closure could not be recorded — the deployer's incident-response procedure must decide whether to revoke or to retry the confirm).

**Where the test PKI is built.** `src/test/java/eu/gillstrom/hsm/testsupport/TestPki.java` — a BouncyCastle-backed in-memory PKI builder. Usage: build a throwaway root + intermediate + leaf, serialise to PEM strings, hand them to the verifier under test, and assert that PKIX rejects the chain because it does not anchor at the pinned vendor root. This pattern is the core of the fail-closed argument.

---

## Reproducible assertions

A reviewer can make the following assertions by running `mvn -B test` and, if desired, by reading the linked source files.

1. **YubicoVerifierTest.chainNotRootedAtPinnedYubicoRootIsRejected** — asserts that a throwaway chain built with `TestPki` does NOT pass PKIX validation against the pinned Yubico root CA. Core fail-closed guarantee for the Yubico path.
2. **SecurosysVerifierTest.fakeChainIsNotRootedAtPinnedSecurosysRoot** — as above, but for Securosys. Directly substantiates Article 1 §4.2's claim that verification is independent of the entity being verified.
3. **SecurosysVerifierTest.tamperedSignatureIsRejected** — demonstrates that once a cryptographic signature in the attestation evidence is modified by a single byte, verification fails. Corresponds to Article 1 §4.2's determinism claim.
4. **SecurosysVerifierTest.emptyChainProducesError** — a missing chain is treated as non-compliance, not silent success.
5. **AzureHsmVerifierTest.chainNotRootedAtPinnedTrustAnchorIsRejected** — as above, but for Azure Managed HSM. In production the trust anchor is Microsoft's published attestation CA; in this reference build it is the placeholder configured in `ATTESTATION_TRUST_ANCHOR`.
6. **AzureHsmVerifierTest.missingCertificatesFieldIsRejected** — structural check: attestations without the `certificates` field cannot pass.
7. **GoogleCloudHsmVerifierTest.chainNotRootedAtPinnedTrustAnchorIsRejected** — parallel to Azure; in production the trust anchor is Google's published attestation CA (Marvell LiquidSecurity is the underlying hardware shared with Azure, but Google's CA is the practical pinning point).
8. **GoogleCloudHsmVerifierTest.emptyChainIsRejected** — empty input is a rejection, not a default-accept.
9. **BankIdServiceTest.invalidBase64InputReturnsInvalid** — the service rejects malformed input up front rather than raising internal errors.
10. **BankIdServiceTest.xmlWithoutSignatureElementReturnsInvalidWithDsigError** — a BankID response without an XML-DSig `<Signature>` element is rejected. Substantiates Article 1 §5.6's claim that `usrVisibleData` is never trusted without cryptographic verification.
11. **BankIdServiceTest.emptyInputReturnsInvalid** — edge-case determinism.
12. **FailClosedSignatoryRightsVerifierTest.alwaysReturnsUnknown / unknownForNullInputsToo** — asserts the default is UNKNOWN, not AUTHORISED. Corresponds to Article 1 §5.6's invändning 5 (alternative mechanisms must satisfy deterministic reproducibility without institutional trust).
13. **MockAgreementRegistrySignatoryRightsVerifierTest** — loads a JSON registry from `@TempDir` and asserts AUTHORISED / UNAUTHORISED exactly corresponds to the registered pairs. Demonstrates the integration shape without shipping real registry credentials.

Reviewer takeaway: the verifier core is deterministic, fail-closed, and independent of any network call or human institution. That is the falsifiable claim the articles make; these tests are the falsification harness.

---

## Configuration knobs

All of these are Spring `@Value` / `@ConditionalOnProperty` properties. Reference defaults are shown first; the production value a deploying organisation should set is shown second.

| Property | Reference default | Production value | Source |
| -------- | ----------------- | ---------------- | ------ |
| `swish.signatory-rights.mode` | `fail-closed` (implicit default) | `real-registry` (must be supplied by the deployer; reference does not ship one) | `FailClosedSignatoryRightsVerifier.java`, `MockAgreementRegistrySignatoryRightsVerifier.java` |
| `swish.signatory-rights.mock-file` | `classpath:signatory-rights.json` | N/A — only used with `mock-registry` | `MockAgreementRegistrySignatoryRightsVerifier.java` |
| `logging.level.eu.gillstrom.hsm` | `INFO` | `INFO` or `WARN` (reduce verbosity in prod) | `application.yaml` |
| `server.port` | `8080` | site-specific | `application.yaml` |

Notes:

- There is **no mTLS knob in this repo** — that lives in the `gatekeeper/` repo's `SecurityConfig`. This repo is the verifier library + BankID + CSR issuance flow, not a supervisory API.
- **`signatory-rights.mode=fail-closed` is the correct production default** when no real registry adapter is wired in. It hard-fails SIGNING requests (which is what you want) rather than silently authorising.

---

## Known limitations and their scope

Each limitation below declares: (a) what the risk is, (b) what the reference implementation does to mitigate it, (c) what would close it in production.

### Marvell TLV parser is speculative (High)

- **Risk.** `AzureHsmVerifier` and `GoogleCloudHsmVerifier` parse the Marvell attestation blob with TLV reading code that assumes the signature is the last N bytes of the blob. Tag constants (`0x0102`, `0x0100`, `0x0162`, `0x0350` etc.) were inferred from open-source samples rather than Marvell's published specification.
- **Mitigation in reference.** Fail-closed on any parse failure; a partial or malformed blob is rejected, not silently accepted. The chain validation against the pinned attestation trust anchor remains sound regardless of attribute-parse correctness.
- **Close in production.** Replace with a real Marvell blob parser extracted from vendor documentation. This is a shared concern with the sibling gatekeeper repo.

### Signatory-rights verification is a placeholder (Critical for production)

- **Risk.** No real query to Swish agreement registry or Bolagsverket. A deployment that forgot to wire a real adapter would hard-fail every SIGNING request — which is acceptable — but any accidental switch to `mock-registry` with a misconfigured JSON file would produce non-authoritative authorisations.
- **Mitigation in reference.** Default is `FailClosedSignatoryRightsVerifier` which logs `WARN` at startup and on every invocation. Impossible to miss in operational logs.
- **Close in production.** Implement a `SignatoryRightsVerifier` backed by the Swish agreement registry or Bolagsverket, and activate it via `swish.signatory-rights.mode=real-registry` (name of your choice — the abstraction is pluggable).

### BankID test vectors are not bundled (Medium)

- **Risk.** A reviewer cannot exercise a full happy-path BankID flow locally.
- **Mitigation in reference.** `BankIdServiceTest` exercises negative paths (malformed base64, missing `<Signature>` element) deterministically. The positive path requires real BankID-signed material, which BankID's licensing terms do not permit bundling.
- **Close in production.** Deployments use real BankID production or test-environment material; this is not a reference-implementation concern.

### Revocation checking disabled in PKIX validation (Low — deliberate)

- **Risk.** A revoked attestation certificate would still validate the chain.
- **Mitigation in reference.** Attestation PKI is closed-vendor and the attestation itself is a point-in-time assertion about key generation, so CRL/OCSP has less meaning than for public-web PKI. This is documented inline in each verifier's `verifyCertChain` method.
- **Close in production.** For BankID specifically, the separate structural OCSP check in `BankIdService.checkOcsp` (BouncyCastle `BasicOCSPResp`) provides authoritative status from Finansiell ID-Teknik. For HSM attestation, a vendor-provided revocation feed would need to be integrated.

### In-memory PKI for tests (by design)

- **Risk.** None; it is the design.
- **Mitigation in reference.** `TestPki` builds a throwaway PKI in memory; tests assert PKIX *rejects* this throwaway chain because it does not anchor at the pinned vendor root. This is the correct fail-closed test.
- **Close in production.** Not applicable.

---

## Regulatory mapping

| Regulatory source | Code reference |
| ----------------- | -------------- |
| DORA Regulation (EU) 2022/2554 Article 5(2)(b) (authenticity / integrity, management body) | Attestation chain verification — `AttestationService.verifyAndIssue()` delegates to vendor verifier, which uses PKIX `CertPathValidator` against pinned root |
| DORA Regulation (EU) 2022/2554 Article 6(10) (verification of compliance, retained financial-entity responsibility) | `AttestationService.java` Phase 2 calls `GatekeeperClient.verify(...)`; the supervisory cross-check is in the sibling `gatekeeper/` repo |
| DORA Regulation (EU) 2022/2554 Article 9(3)(c) (prevent data corruption) | Non-exportability and origin assertions extracted by each verifier from the attestation evidence |
| DORA Regulation (EU) 2022/2554 Article 9(4)(d) (strong authentication mechanisms) | Attestation chain is the mechanism that authenticates the key's hardware origin — verified by `verifyCertChain()` |
| DORA Regulation (EU) 2022/2554 Article 28(1)(a) (full responsibility irrespective of outsourcing) | `verifyAndIssue()` is a structural check at issuance time; the financial entity cannot outsource the verification itself, per Article 1 §3.2 |
| DORA Regulation (EU) 2022/2554 Article 28(6) (5-year retention of records) | The `IssuanceResponse` returned by `verifyAndIssue()` is the financial entity's retention object. Each `IssuanceResponse` carries the gatekeeper-signed `VerifyResponse` and the closing `IssuanceConfirmResponse`; retention happens on the entity side. The gatekeeper repo carries the corresponding 5-year append-only audit log. |
| DORA Regulation (EU) 2022/2554 Article 30(2)(c) (contractual terms on protection of data) | Article 2 §4.2 argues that contractual HSM requirement without verification does not satisfy Article 30(2)(c); this repo is the verification mechanism that closes that gap |
| EBA Regulation (EU) No 1093/2010 Article 17 (breach-of-Union-law procedure) | The supervisory gatekeeper that produces receipts under Phase 2 is the operational embodiment of the verification mechanism that the Article 17 procedure presupposes; client side cooperates by retaining the receipts |
| EBA Regulation (EU) No 1093/2010 Article 29 (supervisory convergence) | Cross-Member-State convergence consumes the same `VerifyResponse` byte format from any operating NCA gatekeeper — see `WireFormatGoldenBytesTest` |
| eIDAS Regulation (EU) No 910/2014 Article 25 / Article 29 / Annex II | NOT in scope of this repo: the Swish Utbetalning RSA-4096 signatures operate under contract law + DORA, not under eIDAS qualified-signature governance. The Primus HSM is QSCD-capable (see HARDWARE_BASELINE.md) but SKA is not activated |
| ISO/IEC 27001:2022 A.8.24 (use of cryptography) | Verification is the evidence-producing mechanism for A.8.24 per Article 2 §6.5 |
| ISO/IEC 27001:2022 A.5.9 (inventory of information assets) | `AttestationService` binds attested properties to CSR subjects, creating a verifiable inventory line per Article 2 §4.1 |

---

## How to extend

The repository's obvious extension points are:

1. **Real `SignatoryRightsVerifier` adapter.** Implement the interface in `src/main/java/eu/gillstrom/hsm/service/SignatoryRightsVerifier.java`; Spring's `@ConditionalOnProperty` will wire it in based on the `swish.signatory-rights.mode` value. The `FailClosedSignatoryRightsVerifier` and `MockAgreementRegistrySignatoryRightsVerifier` are templates.
2. **Real Marvell TLV parser.** Replace the hand-rolled TLV code in `AzureHsmVerifier` and `GoogleCloudHsmVerifier` with a parser derived from Marvell's published attestation specification. Ideally factor into a shared helper since both cloud verifiers consume the same blob format.
3. **Additional vendor verifier.** Implement `HsmAttestationVerifier` for additional HSM lines (Thales Luna, Entrust nShield, AWS CloudHSM). Follow the pattern in `SecurosysVerifier`: constructor loads the pinned root from classpath and throws `IllegalStateException` on failure; `verifyCertChain()` uses PKIX `CertPathValidator` with the root as sole trust anchor; `verifyAttestedProperties()` extracts `non_exportable` + `generated_on_device` + `device_serial`.
4. **Hook into `gatekeeper/`.** The gatekeeper repo consumes verification results through its own vendor verifiers (parallel hierarchy). A production deployment can either re-use this repo's verifier classes as a library dependency, or keep them in-repo — the split between this repo and the gatekeeper repo is historical (attestation-reference was the initial artefact; gatekeeper was layered on top for supervisory use).
5. **Replace BankID XML-DSig trust anchors.** The current implementation loads BankID's production / test CAs; a deployer swapping to a different eID scheme (Swedish Freja, another Member State's eIDAS node) replaces the trust anchors and the XML-DSig ID-attribute scoping in `markBankIdSignedDataId()` may need to be re-targeted for the new scheme's signed-data element.
