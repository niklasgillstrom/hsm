# Peer-review guide — hsm

This document is written for a peer reviewer of Article 1 (Gillström, in preparation; target venue: *Capital Markets Law Journal*) and Article 2 (Gillström, in preparation; target venue: *Computer Law & Security Review*) who wants to reproduce the central verification claims these articles make. Companion repos `gatekeeper/` and `railgate/` complete the **triadic system** (since v1.2.0) described in Article 1 §4.2 and Article 2 §9.3:

- **hsm** (this repo) carries the verifier core and the BankID-based certificate-issuance flow that surrounds it.
- **gatekeeper** is the NCA-facing supervisory API shell that wraps those verifiers for regulatory use, and from v1.1.0 also exposes the settlement-time signature verification endpoint that railgate consumes.
- **railgate** is the central-bank settlement-rail enforcement layer that calls gatekeeper's verification endpoint at settlement time (RIX-INST in Sweden; generalisable to TIPS, FedNow, FPS, NPP).

The three components together operationalise the data-minimised quadruple-triangulation model: only digest, signature, and certificate identifiers traverse the supervisor boundary — no transaction payload content is exposed at any layer.

## Version 1.3.0 — what changed and what to verify

A systematic check of the triad against its own documentation found places where a described protection was not implemented in the code. v1.3.0 fixes them and records what was wrong; see "Corrections after documentation-versus-code review" below for the full account. In summary, for hsm:

- Azure and Google attestation attributes are no longer asserted without being parsed; both verifiers fail closed with an explicit error code.
- An empty certificate path no longer counts as a validated chain in the Yubico, Azure and Google verifiers.
- BankID chain validation no longer takes its trust anchor from the caller-supplied chain. The `OU=BankID Member Banks CA` roots are pinned and the service refuses to start without them.
- BankID OCSP verification now follows all seven steps of BankID's published procedure, where it previously performed two.
- Payload is read only from inside the element the signature's Reference covers.
- New `BankIdSignatureVerificationTest` and `BankIdFixture`: nine tests, eight of them rejections, against synthetic material.

Reviewers should start with `mvn -B test` (51 tests, no network, no HSM, no BankID) and then read the corrections section.

---

## Version 1.2.0 — what's new for hsm reviewers

hsm carried **no code changes** in v1.2.0 relative to v1.0.0. (Superseded: the verifier core and the BankID flow have since been changed — see "Corrections after documentation-versus-code review" below.) The version bump aligns hsm with the gatekeeper and railgate companion artefacts so the trio carries a uniform version number, and ships updated cross-references (`CROSS_REFERENCE.md`) plus this peer-review-guide section so reviewers can navigate the triadic system from any of the three repositories. The verifier core and the BankID-issuance flow in this repo are unchanged and reviewers' reproducible-assertion notes from v1.0.0 still apply unchanged.

---

## What this repo is / isn't

**Is:**

- A **reference implementation** of the HSM attestation verification procedure described in Article 1 §§4.1–4.2. Nine vendor-specific verifiers (Securosys, Yubico, Azure Managed HSM, Google Cloud HSM, Marvell LiquidSecurity, Thales Luna, Crypto4A QASM, Fortanix DSM, Entrust nShield) plug into a common `HsmAttestationVerifier` interface. Each anchors its chain at a pinned vendor root: PKIX for Securosys, Yubico and Fortanix, issuer name and signature for the three Marvell chains, Thales Luna and Crypto4A, and the warrant's signatures from the pinned KWARN-1 key for Entrust nShield, as the vendors' tools check them.
- A **demonstrator** of the end-to-end certificate-issuance flow: a CSR + attestation evidence → `AttestationService.verifyAndIssue()` → BankID-authenticated signatory → pluggable signatory-rights check → `IssuanceClient.issue()` (reference: `MockIssuanceClient`).
- **Deterministically reproducible**. The PKIX-based test suite builds a throwaway CA with `TestPki` and asserts that non-pinned chains are rejected — no network, no mocks, no vendor hardware required.
- **MIT-licensed**.

**Isn't:**

- Production code. The `SignatoryRightsVerifier` default is `fail-closed` (intentional). For the current state of the Azure, Google and Marvell paths see the vendor table in `README.md` (gated by `MARVELL_FORMAT_UNCONFIRMED`); for the history of the attribute handling and the BankID trust anchors, see "Corrections after documentation-versus-code review" below.

### Corrections after documentation-versus-code review

Checking this document against the code found several places where it described a protection the code did not implement. The code has been changed; this section records what was wrong, so the record is not silently rewritten.

- **Azure/Google key attributes were asserted, not verified.** `AzureHsmVerifier` hardcoded `exportable=false` and `keyOrigin="generated"` without parsing the attestation blob, and `GoogleCloudHsmVerifier` treated an absent extractability tag (`0x0162`) as proof of non-extractability. Two of the four compliance conjuncts were therefore satisfied without anything being checked, so an imported or exportable cloud-HSM key could be reported COMPLIANT. This guide previously described that path as fail-closed; it was fail-open. Both verifiers now fail closed with `AZURE_ATTRIBUTES_UNVERIFIED` / `GOOGLE_ATTRIBUTES_UNVERIFIED`. Structural support for the cloud paths (vendor routing, chain validation, signature and public-key binding) is unaffected; the attribute step is explicitly unverified until a deployer supplies a parser. (Superseded in 1.6.0: a parser built from Marvell's published format and the vendors' tools ships in `MarvellAttestation`, the two `*_ATTRIBUTES_UNVERIFIED` codes are gone, and the cloud paths are refused with `MARVELL_FORMAT_UNCONFIRMED` until a real attestation confirms the format.) The Marvell TLV specification is NDA-restricted and no parser ships here.
- **An empty certificate path was treated as a valid chain.** `YubicoVerifier`, `AzureHsmVerifier` and `GoogleCloudHsmVerifier` returned `chainValid=true` when the submitted chain contained only the pinned root, which is publicly downloadable — no PKIX validation ran in that branch. All three now return `false`, matching `SecurosysVerifier`.
- **BankID chain validation had no trust anchor.** `BankIdService` used the last certificate of the caller-supplied chain as the `TrustAnchor`, with only a substring check for "BankID" in the DN. A self-signed root with a matching CN, together with a user certificate carrying any personal identity number, validated. Roots are now pinned as constants and loaded in the constructor; the service refuses to start if they cannot be loaded, and the DN substring check is removed.
- **BankID OCSP was matched, not verified.** `checkOcsp` matched the certificate serial and read `producedAt`, and nothing else: the responder certificate was not verified, the signature on the response was not verified, `CertStatus` was never read (so a revoked certificate passed), the responder's issuer was not compared against the user certificate's, and the nonce was never checked (so a response issued for one signature could be replayed against another). Measured against BankID's seven-step procedure for verifying signatures, the implementation performed steps 4 and 7 only. It now performs all seven. On step 6 the procedure requires the nonce to match "digest of signature" without specifying the construction; measured against production responses, the first 20 bytes of the 32-byte nonce are SHA-1 over the base64 string of the signature, and the remaining 12 bytes vary between responses and are not derivable from the signature, so only the first 20 are compared.
- **Signed payload was read from the whole document.** `usrVisibleData`, `usrNonVisibleData`, `srvInfo` and `signingTime` were read with `getElementsByTagName` across the entire document rather than from inside the element the signature's Reference covers. An element placed outside the signed data and earlier in document order would be returned in preference to the signed one, and the signature would still validate, because the injected element is not part of what was signed. Reads are now scoped to a single `bankIdSignedData` element, and a document where that element is missing or duplicated is rejected.
  The pinned roots are `BankID Root CA v1` and, only when `swish.bankid.allow-test-root=true` (set in `application-dev.yaml` only, since 1.5.0), `Test BankID Root CA v1 Test`, both under `OU=BankID Member Banks CA`. Swedish BankID personal certificates chain through the issuing bank to that root, so one anchor covers every bank and the intermediates travel inside the signature. Not to be confused with `BankID SSL Root CA v1` (`OU=Infrastructure CA`), which anchors the mTLS channel to the RP API — a different hierarchy, and pinning it here would reject every valid signature. Verified empirically: a production signature chain (`user -> SEB Customer CA3 v1 for BankID -> SEB CA v1 for BankID`) passes PKIX against the pinned production root and fails against the SSL root. Both roots are delivered by BankID on request; check a candidate by confirming that its Subject Key Identifier equals the Authority Key Identifier of the bank CA at the top of a real signature chain (production: `67:8A:BA:B2:EA:48:1C:7A:F5:3B:68:37:27:72:06:EB:91:63:CB:53`).
- An eIDAS Qualified Trust Service. Certificate issuance here is reference-quality, not a QTSP.
- A complete production HSM integration. The HSM-side configuration, audit pipeline, and operational infrastructure that the Swish case study runs on are documented in `HARDWARE_BASELINE.md` (separate document, sibling to this repo).

**What is pinned.** Each verifier embeds its trust anchors as Java text-block constants in the verifier source (e.g., `private static final String YUBICO_ROOT_CA = """ ... """;` for the Yubico verifier; `MARVELL_ROOT_PEM` and `MARVELL_LS2_ROOT_PEM` in `MarvellAttestation` and `HAWKSBILL_ROOT_PEM` in `GoogleCloudHsmVerifier` for the cloud-HSM verifiers) and parses it in the constructor. A load failure is fatal: the constructor throws `IllegalStateException` and Spring Boot refuses to start. Classpath resources under `src/main/resources/` are limited to `application.yaml` and `application-dev.yaml`; the trust anchors do not live there.

**Real vendor-issued roots** are embedded for the Securosys Primus path and the Yubico YubiHSM path. The Yubico root is sourced from `https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem`; SHA-256 fingerprint `09:4A:3A:C4:...:39:2F:B7:24` documented inline above the PEM constant in `YubicoVerifier.java`.

**What is placeholder.**

- **Gatekeeper client default is fail-closed.** `swish.gatekeeper.mode=fail-closed` is the default; `FailClosedGatekeeperClient` throws `GatekeeperException` on every call. This is the production-safe default — it forces a deployer to consciously wire `swish.gatekeeper.mode=http` and `swish.gatekeeper.url` against an authoritative NCA endpoint before any signing certificate can be issued. The `mock` mode is for demonstration and CI only; it auto-registers an ephemeral RSA key in the local `GatekeeperKeyRegistry` and emits a startup `WARN` log so the non-authoritative posture cannot be missed.
- **Cloud-HSM attestation format unconfirmed.** `AzureHsmVerifier` and `GoogleCloudHsmVerifier` share `MarvellAttestation`, built on Marvell's "LiquidSecurity HSM - Software Key Attestation" page and `verify_pubkey.py`, Microsoft's MIT-licensed parser and validator and Google's owner chain (Hawksbill Root v1 prod). The key is bound through the modulus or EKCV in the signed blob, which neither cloud vendor's tool reads; `MarvellAttestationTest.marvellPublishedExampleBindsItsKey` runs Marvell's published example values. No real Azure or Google attestation has been run through it, so both verifiers add `MARVELL_FORMAT_UNCONFIRMED` and never report a valid attestation until one is committed as a fixture.
- **`SignatoryRightsVerifier` default** — `FailClosedSignatoryRightsVerifier` returns UNKNOWN on every call and emits a `WARN` log. The `MockAgreementRegistrySignatoryRightsVerifier` reads a JSON file. Neither is a Swish or Bolagsverket adapter.
- **Marvell parser** — follows the vendors' published tools, not Marvell's non-public specification; see the item above.

---

## Reproducibility contract

A reviewer can independently reproduce different layers of the supervisory flow depending on which fixtures and which gatekeeper they have access to.

| Layer | What runs without external infrastructure | What requires a deployed NCA gatekeeper |
| ----- | ------------------------------------------ | ---------------------------------------- |
| Local verification (Phase 1) | `mvn -B test` — all 241 tests (1.6.0) run without network, HSM or BankID. | Nothing additional. |
| Gatekeeper verify + confirm (Phases 2 + 4) | `GatekeeperFlowTest` runs against `MockGatekeeperClient`, an in-process gatekeeper that signs receipts with an ephemeral RSA key registered in the local trust store. The byte-identity of the canonical receipt is locked by `WireFormatGoldenBytesTest` — any drift between this repo's canonicalizer and the gatekeeper repo's canonicalizer breaks the assertion in **both** repos at the same time. | An end-to-end test against a live `gatekeeper` instance (with mTLS configured, an issuer-CA bundle for Step 7, and `gatekeeper.signing.mode=configured` against a real seal certificate) requires deploying the gatekeeper — see `gatekeeper/PEER_REVIEW_GUIDE.md`. |
| Real attestation evidence | `RealAttestationFixtureTest` exercises real Yubico and Securosys fixtures against the pinned vendor roots. No HSM hardware required at test-run time; the fixtures were captured at the originating site. | Fresh HSM hardware is only required to capture **new** fixtures. |
| Cross-repo byte-format compatibility | `WireFormatGoldenBytesTest` in this repo asserts a hardcoded golden string. The same string is asserted in the gatekeeper repo's `WireFormatGoldenBytesTest`. Any deviation fails both tests. | Nothing additional. |

The mock gatekeeper deliberately produces real cryptographic signatures (RSA-2048, `SHA256withRSA`) that the local `ReceiptVerifier` validates with the same code path that production HTTP gatekeeper traffic uses. The only thing the mock loses relative to a real NCA gatekeeper is the legal weight of the seal — the cryptographic shape is identical, which is what makes the supervisory flow falsifiable in this repo's test harness alone.

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

**Mutation testing.** `mvn -Ppit test-compile org.pitest:pitest-maven:mutationCoverage` runs PIT 1.30.0 over all production classes (reports in `target/pit-reports/`). First run, 1.6.0: 2 094 mutations, 1 585 killed (76 %), test strength 88 %, 298 without test coverage. The survivors are listed per class in `mutations.csv`; most lie in BankID parsing, the Marvell parser and the Securosys and Yubico verifiers.

Test count at submission time: **26 tests across 9 test classes** (241 tests across 40 classes in 1.6.0), split into four layers:

- **Synthetic fail-closed tests** under `eu.gillstrom.hsm.{verification,service}` — these build throwaway PKIs in memory with `TestPki` and assert that the verifier rejects every chain that does not anchor at the pinned vendor root. They prove the *structural* fail-closed contract.
- **`BankIdSignatureVerificationTest` (9 tests at submission, 27 in 1.6.0)** covers the BankID path end to end against material generated by `BankIdFixture`: a throwaway root, bank CA, personal certificate and OCSP responder, an XML-DSig-signed response and a signed OCSP response whose nonce binds to it. One test is the accepted case; the other eight are the rejections that matter — revoked certificate, OCSP response signed with the wrong key, responder issued by a different CA, a response legitimately issued for one signature presented with another, a response with no nonce, payload injected outside the element the Reference covers, a duplicated `bankIdSignedData`, and a chain not rooted at the pinned anchor.
- No recorded production BankID signature is bundled, and none should be: it would carry a real personal identity number and the text of a real agreement. A synthetic fixture is also the stronger instrument — a recording can only show that a correct case is accepted, whereas the fixture produces the manipulations the repository claims to reject. `BankIdFixture` self-checks each signature it generates, so a broken fixture is distinguishable from a broken verifier.
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
5. **AzureHsmVerifierTest.jwkNamingTheCsrKeyIsNotABinding** — the unsigned JWK in the `az` JSON does not bind the attestation to the CSR key; only the modulus inside the signed blob does. Fails on 1.5.0, where the key was taken from the JWK.
6. **AzureHsmVerifierTest.unconfirmedFormatIsNeverValid** — while `MarvellAttestation.FORMAT_CONFIRMED_BY_REAL_SAMPLE` is false, a well-formed attestation of the CSR key is still not valid.
7. **GoogleCloudHsmVerifierTest.ownerChainIsRequired** — without the owner chain under Hawksbill Root v1 prod, carrying the manufacturer card and partition keys, the attestation is refused.
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
| `swish.signatory-rights.mock-registry.path` | `classpath:signatory-rights.json` (no such file ships) | N/A — only used with `mock-registry` | `MockAgreementRegistrySignatoryRightsVerifier.java` |
| `logging.level.eu.gillstrom.hsm` | `INFO` | `INFO` or `WARN` (reduce verbosity in prod) | `application.yaml` |
| `server.port` | `8080` | site-specific | `application.yaml` |

Notes:

- mTLS in this repo: the client side towards the gatekeeper (`swish.gatekeeper.ssl-bundle`), and the caller's transport certificate on the API (`swish.caller-binding`, with `server.ssl.client-auth=need` set by the deployment). The supervisory API's mTLS lives in the `gatekeeper/` repo's `SecurityConfig`.
- **`signatory-rights.mode=fail-closed` is the correct production default** when no real registry adapter is wired in. It hard-fails every request, SIGNING and TRANSPORT alike (which is what you want) rather than silently authorising.

---

## Known limitations and their scope

Each limitation below declares: (a) what the risk is, (b) what the reference implementation does to mitigate it, (c) what would close it in production.

### Marvell attestation format is unconfirmed (High)

- **Risk.** `MarvellAttestation` follows Marvell's "LiquidSecurity HSM - Software Key Attestation" page and the vendors' tools, but whether Azure's and Google's blobs use exactly that layout is unconfirmed.
- **Mitigation in reference.** Strict parsing inside the signed data (a blob that fits both layouts or neither is rejected); every attribute must be present; `MARVELL_FORMAT_UNCONFIRMED` keeps both cloud verifiers from ever reporting a valid attestation.
- **Close in production.** Commit a real Azure Managed HSM and a real Google Cloud HSM attestation as fixtures, confirm the layout and the modulus attribute against them, and set `FORMAT_CONFIRMED_BY_REAL_SAMPLE`. This is a shared concern with the sibling gatekeeper repo.

### Signatory-rights verification is a placeholder (Critical for production)

- **Risk.** No real query to Swish agreement registry or Bolagsverket. A deployment that forgot to wire a real adapter would hard-fail every request, SIGNING and TRANSPORT — which is acceptable — but any accidental switch to `mock-registry` with a misconfigured JSON file would produce non-authoritative authorisations.
- **Mitigation in reference.** Default is `FailClosedSignatoryRightsVerifier` which logs `WARN` at startup and on every invocation. Impossible to miss in operational logs.
- **Close in production.** Implement a `SignatoryRightsVerifier` backed by the Swish agreement registry or Bolagsverket, and activate it via `swish.signatory-rights.mode=real-registry` (name of your choice — the abstraction is pluggable).

### BankID test vectors are not bundled (Medium)

- **Risk.** A reviewer cannot exercise a full happy-path BankID flow locally.
- **Mitigation in reference.** `BankIdServiceTest` exercises negative paths (malformed base64, missing `<Signature>` element) deterministically. The positive path requires real BankID-signed material, which BankID's licensing terms do not permit bundling.
- **Close in production.** Deployments use real BankID production or test-environment material; this is not a reference-implementation concern.

### Revocation checking disabled in PKIX validation (Low — deliberate)

- **Risk.** A revoked attestation certificate would still validate the chain.
- **Mitigation in reference.** Attestation PKI is closed-vendor and the attestation itself is a point-in-time assertion about key generation, so CRL/OCSP has less meaning than for public-web PKI. This applies to every verifier: none checks revocation of the attestation chain.
- **Close in production.** For BankID specifically, the separate structural OCSP check in `BankIdService.checkOcsp` (BouncyCastle `BasicOCSPResp`) provides authoritative status from Finansiell ID-Teknik. For HSM attestation, a vendor-provided revocation feed would need to be integrated.

### In-memory PKI for tests (by design)

- **Risk.** None; it is the design.
- **Mitigation in reference.** `TestPki` builds a throwaway PKI in memory; tests assert PKIX *rejects* this throwaway chain because it does not anchor at the pinned vendor root. This is the correct fail-closed test.
- **Close in production.** Not applicable.

---

## Regulatory mapping

| Regulatory source | Code reference |
| ----------------- | -------------- |
| DORA Regulation (EU) 2022/2554 Article 5(2)(b) (authenticity / integrity, management body) | Attestation chain verification — `AttestationService.verifyAndIssue()` delegates to the vendor verifier, which checks the attestation up to the vendor's pinned root (PKIX `CertPathValidator` for Securosys, Yubico and Fortanix; explicit signature checks for the others) |
| DORA Regulation (EU) 2022/2554 Article 6(10) (verification of compliance, retained financial-entity responsibility) | `AttestationService.java` Phase 2 calls `GatekeeperClient.verify(...)`; the supervisory cross-check is in the sibling `gatekeeper/` repo |
| DORA Regulation (EU) 2022/2554 Article 9(3)(c): ICT solutions and processes shall "prevent the lack of availability, the impairment of the authenticity and integrity, the breaches of confidentiality and the loss of data" | Non-exportability and origin assertions extracted by each verifier from the attestation evidence |
| DORA Regulation (EU) 2022/2554 Article 9(3)(d): ICT solutions and processes shall "ensure that data is protected from risks arising from data management, including poor administration, processing-related risks and human error" | A third party can verify offline, against a published vendor root and without a human witness or the involvement of the vendor or the financial entity, that an individual key was generated in the HSM and cannot be exported from it (the inclusion criterion in `README.md`) |
| DORA Regulation (EU) 2022/2554 Article 9(4)(d): financial entities shall "implement policies and protocols for strong authentication mechanisms, based on relevant standards and dedicated control systems, and protection measures of cryptographic keys whereby data is encrypted based on results of approved data classification and ICT risk assessment processes" | Attestation chain is the mechanism that authenticates the key's hardware origin — verified by each vendor verifier up to its pinned root |
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
2. **Real Marvell fixtures.** Commit a real Azure and Google attestation and open the format gate in `MarvellAttestation` once they verify.
3. **Additional vendor verifier.** Implement `HsmAttestationVerifier` for further HSM lines that meet the inclusion criterion in `README.md` (Thales Luna and Entrust nShield are implemented; AWS CloudHSM is excluded under that criterion). Follow the pattern in `SecurosysVerifier`: constructor parses the pinned root from a text-block constant and throws `IllegalStateException` on failure; `verifyCertChain()` uses PKIX `CertPathValidator` with the root as sole trust anchor; `verifySecurosysAttestation()` extracts the key attributes (`extractable`, `never_extractable`, `sensitive`, `always_sensitive`) and the device serial.
4. **Hook into `gatekeeper/`.** The gatekeeper repo consumes verification results through its own vendor verifiers (parallel hierarchy). A production deployment can either re-use this repo's verifier classes as a library dependency, or keep them in-repo — the split between this repo and the gatekeeper repo is historical (attestation-reference was the initial artefact; gatekeeper was layered on top for supervisory use).
5. **Replace BankID XML-DSig trust anchors.** The current implementation loads BankID's production / test CAs; a deployer swapping to a different eID scheme (Swedish Freja, another Member State's eIDAS node) replaces the trust anchors and the XML-DSig ID-attribute scoping in `markBankIdSignedDataId()` may need to be re-targeted for the new scheme's signed-data element.
