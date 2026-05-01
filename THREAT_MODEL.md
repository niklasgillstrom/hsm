# Threat model — hsm

**Scope.** Threat model for the HSM attestation verification library and the BankID-based certificate-issuance flow surrounding it. The companion repositories `gatekeeper/` (supervisory gatekeeper API + settlement-time signature verification endpoint) and `railgate/` (central-bank settlement-rail enforcement) have their own threat models covering threats specific to those layers. This document focuses on threats specific to the financial-entity side.

**v1.2.0 scope.** No code changes in hsm relative to v1.0.0; the threats and mitigations enumerated below are unchanged. The triadic-system threat surface is covered by the union of the three repositories' THREAT_MODEL.md documents.

**Assumptions out of scope.** The hardware platform on which the code runs, the operating system, the JVM, and the wider network are not modelled here. For the operational environment of the case study deployment, see `HARDWARE_BASELINE.md` §3.1 (locked rack, dual-ISP, UPS, FDE with manual unlock, dual switches, Wazuh SIEM, gapless audit log pipeline). The threat model below treats those as sound and focuses on what the Java code itself can and cannot guarantee.

**Framework.** STRIDE. Each section lists: (a) assets at risk, (b) attack vectors considered, (c) mitigations present in the reference code, (d) residual risks.

---

## Spoofing

### Assets at risk

- **Attested signing key identity.** A CSR-plus-attestation-evidence that claims a signing key was generated in a certified HSM must not pass verification unless that claim is cryptographically supported.
- **BankID-authenticated signatory identity.** `usrVisibleData` / `usrNonVisibleData` in the BankID response must not be attacker-controllable.

### Attack vectors

1. Attacker forges an HSM attestation chain (synthesises an attestation certificate that claims origin in a real Securosys / Yubico / Azure / Google HSM).
2. Attacker submits a legitimate-looking BankID signature XML that has been tampered to replace the signed content.
3. Attacker constructs a certificate chain whose issuer/subject strings contain "Yubico" or "Securosys" but do not actually chain to the vendor root (historical weakness — see below).

### Mitigations

- **Pinned trust anchors** — every verifier (`SecurosysVerifier`, `YubicoVerifier`, `AzureHsmVerifier`, `GoogleCloudHsmVerifier`) embeds a single trust anchor as a Java text-block constant in the verifier source and parses it in the constructor with `CertificateFactory.generateCertificate(...)`. A parse failure throws `IllegalStateException`; Spring Boot refuses to start — the deploy is fail-closed, not fail-open. The Securosys Primus root and the Yubico YubiHSM root are real vendor-issued roots (Yubico SHA-256 `09:4A:3A:...:B7:24`, sourced from `developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem`). The cloud-HSM trust anchor used by both `AzureHsmVerifier` and `GoogleCloudHsmVerifier` is the genuine Marvell/Cavium LiquidSecurity Root CA fetched from Marvell's official distribution — same SHA-256 fingerprint Google Cloud HSM's open-source verification code anchors at. Two known limitations: **(i)** the bundled Marvell root expired 2025-11-16 and the production deployer must rotate to the current Marvell root before validating attestations created after that date; **(ii)** Google's published verification model uses a **dual chain** (Marvell manufacturer + Google's "Hawksbill Root v1 prod" owner root, both anchored independently), and Azure Managed HSM is expected to follow an analogous pattern with a Microsoft-controlled owner root — this verifier implements only the manufacturer chain. Neither limitation weakens the structural fail-closed guarantee for the chains the verifier does validate, but production deployment of either cloud path requires owner-chain validation in addition.
- **PKIX `CertPathValidator`** — chain validation uses `java.security.cert.CertPathValidator.getInstance("PKIX")` with `PKIXParameters` anchored at the pinned root. `BasicConstraints`, `KeyUsage`, path length, and validity dates are enforced by the JCA path validator, not by an ad-hoc loop.
- **BankID XML-DSig signature verification** — `BankIdService.verify()` uses `javax.xml.crypto.dsig.XMLSignatureFactory` with `KeySelector.singletonKeySelector(userCert.getPublicKey())` against the BankID XML. If the signature does not validate, `BankIdResult.invalid(...)` is returned. This closes the vector where `usrVisibleData` was previously attacker-controllable.
- **Strict ID attribute scoping** — `BankIdService.markBankIdSignedDataId(doc)` registers `Id` as the XML-DSig reference target *only* on the designated BankID signed-data element, not on arbitrary elements. This prevents ID-attribute confusion attacks where an attacker could register a colliding `Id` on a manipulated element.

### Residual risks

- **Compromised vendor root CA.** If the HSM manufacturer's CA is compromised, the verifier would accept attestations for attacker-controlled "HSMs". Out of scope for the library; HARDWARE_BASELINE.md §7 identifies this as an inherent property of hardware-attestation schemes.
- **Cloud-HSM trust anchor: rotation-due and owner chain not implemented.** `ATTESTATION_TRUST_ANCHOR` in `AzureHsmVerifier` and `GoogleCloudHsmVerifier` is the genuine Marvell/Cavium LiquidSecurity Root CA from Marvell's official distribution, but it expired 2025-11-16; deployers must rotate to the current Marvell root before relying on chain validation for attestations created after expiry. Independently, Google's published verification model (`verify_chains.py`, 2021) uses a dual chain (Marvell manufacturer + Google's "Hawksbill Root v1 prod" owner root, both anchored independently), and Azure Managed HSM is expected to follow an analogous pattern with a Microsoft-controlled owner root — this verifier implements only the manufacturer chain. Both gaps are fail-closed (not fail-open): with the expired Marvell root or the unbundled owner anchor, post-expiry chains and unverified-owner attestations are rejected, not silently accepted. They are deployment prerequisites for the cloud-HSM paths, not runtime risks. Closing both is a configuration + code edit in `AzureHsmVerifier.java` and `GoogleCloudHsmVerifier.java` (rotate the Marvell root constant; add the cloud vendor's owner-root constant and parallel chain-validation logic).
- **BankID CA compromise.** Same structural residual risk at the eID layer.
- **Clock skew.** PKIX checks validity dates against local clock. Material compromise of the host clock could allow an expired certificate to verify. The case-study deployment mitigates this via GPS-PPS time sync (HARDWARE_BASELINE.md §3.1 time-sync); the code itself trusts the clock.

---

## Tampering

### Assets at risk

- **Attestation evidence content** — the XML / JSON / binary blob submitted to the verifier.
- **BankID XML signed payload** — the `Signature`, `SignedInfo`, and `Reference` subtrees.
- **OCSP response** — the freshness / status evidence for the user certificate.

### Attack vectors

1. **XXE attack on XML input.** Attacker submits attestation evidence or BankID XML with a DOCTYPE and external entity that triggers file reads, SSRF, or billion-laughs-style DoS.
2. **ID-attribute confusion in BankID XML-DSig.** Attacker puts a forged `Id` on a controlled element so `Reference URI="#x"` resolves to attacker content rather than the signed data.
3. **Regex-based parsing bypass.** Historical pattern: regex matched `<tag>...</tag>` and ignored attribute variations, CDATA, namespace prefixes, mixed content.
4. **OCSP byte-scanning false match.** Historical pattern: byte-scanning for `0x18 0x0F` (GeneralizedTime) or `0x02` (INTEGER) collided with encoded values elsewhere in the ASN.1 structure.

### Mitigations

- **XXE-protected `DocumentBuilderFactory`** in both `BankIdService` and `SecurosysVerifier`:
  - `FEATURE_SECURE_PROCESSING` enabled
  - `disallow-doctype-decl` enabled
  - External general and parameter entities disabled
  - `load-external-dtd` disabled
  - `setXIncludeAware(false)`
  - `setExpandEntityReferences(false)`
- **DOM-based field extraction** (`getElementsByTagName` / `getElementsByTagNameNS`) replaces regex throughout.
- **Stricter ID-attribute scoping in BankID** — `markBankIdSignedDataId(doc)` only marks the one element that BankID's enveloping-signature profile expects as the signed-data root.
- **Structural OCSP parsing via BouncyCastle** — `BankIdService.checkOcsp()` uses `OCSPResp` / `BasicOCSPResp` / `SingleResp` and matches against the user certificate's `CertID.SerialNumber`, eliminating the byte-scanning collision surface. `BasicOCSPResp.getProducedAt()` is the authoritative source for OCSP time.
- **Public-key equality via `MessageDigest.isEqual`** — public-key equality comparisons across XML-extracted keys vs CSR keys use constant-time comparison where relevant.

### Residual risks

- **XXE in indirect consumers.** The library exposes `verify()` methods that take strings. Any caller that itself parses the same XML without XXE protection re-opens the hole. Addressed by having all parsing inside the library.
- **OCSP response freshness.** BouncyCastle provides `producedAt`; the library does not enforce a maximum age. Callers that require "OCSP produced within X minutes of attestation" must add that check.

---

## Repudiation

### Assets at risk

- **Record of which signatory authorised an issuance.** BankID `signatoryPersonalNumber` + timestamp.
- **Record of which attestation was verified.** The device serial, chain, and result.

### Attack vectors

1. A signatory later denies having authorised an issuance.
2. An operator later denies that a particular attestation passed / failed verification.

### Mitigations

- **BankID signature verification** — the `usrVisibleData` the signatory saw is cryptographically bound to the BankID signature. Post-hoc denial is contradicted by the signed data.
- **OCSP producedAt** — `BasicOCSPResp.getProducedAt()` provides an authoritative, Finansiell-ID-Teknik-signed timestamp for the user certificate's status at the time of issuance.
- **Structured logging** — SLF4J throughout the verifiers and services; every failure path emits `log.warn(...)` with context.

### Residual risks

- **No tamper-evident log in this repo.** The sibling gatekeeper repo is where receipt signing lives. This repo's output is whatever the caller captures. A caller that uses plain stdout logs without downstream tamper-evidence gets plain stdout-level non-repudiation. The case-study operational deployment feeds logs into a Wazuh SIEM with chain-of-custody controls (HARDWARE_BASELINE.md §3.1).
- **Clock source trust.** Repudiation defence depends on the timestamp being correct. See Spoofing — clock skew.

---

## Information disclosure

### Assets at risk

- **Swedish personal number (`personalNumber`)** — personally identifying information subject to GDPR.
- **Attestation evidence** — not secret by design (HARDWARE_BASELINE.md §10), but caller-held copies should be handled as operational data.
- **Private keys** — by construction never in this code path: the library never sees an HSM's private key material.

### Attack vectors

1. Personal number leaks into debug logs or error responses.
2. Attestation evidence is treated as secret and lost, requiring re-issuance.
3. Exception stack traces expose internal state to unauthenticated callers.

### Mitigations

- **`maskPersonalNumber()` applied at response-construction site** — `AttestationService.java` calls `maskPersonalNumber(bankIdResult.getPersonalNumber())` when populating the outward `VerificationResponse`. The first 6 digits are preserved (YYMMDD, derivable from public context anyway) and the last 4 digits are masked. This prevents raw PNR from leaking into response bodies or downstream logs.
- **No secret in attestation evidence.** Attestation evidence is publicly verifiable by design. Disclosure does not degrade security (HARDWARE_BASELINE.md §10 + attack-vector row 23).
- **Private key not in this code path.** The code verifies attestations; it never holds HSM private keys. `verifySignatoryRights()` takes only public-key fingerprints, not key material.
- **Structured exceptions** — failure paths return `VerificationResponse` objects with bounded error enums rather than raw stack traces. Internal exceptions are logged via SLF4J, not returned.

### Residual risks

- **Masked PNR is still partially identifying.** YYMMDD is recoverable and narrows the Swedish population materially. Sufficient for operational logs; not sufficient for general-purpose data sharing.
- **Callers controlling logging levels.** A caller who sets `logging.level.eu.gillstrom.hsm=DEBUG` may capture verbose internal state. This is a deliberate trade-off for operational debuggability.

---

## Denial of service

### Assets at risk

- **Availability of the verifier.** A malformed input that consumes excessive CPU, memory, or file descriptors would starve legitimate requests.
- **Availability of the BankID / OCSP paths.** Similar concerns.

### Attack vectors

1. **Billion laughs / XML bomb.** Addressed by XXE mitigations above — DOCTYPE is rejected.
2. **Very large attestation blob.** An attacker submits a multi-megabyte blob full of certificates to exhaust CPU during PKIX validation.
3. **Malformed certificate forcing slow path in `CertificateFactory`.**
4. **OCSP with many `SingleResp` entries forcing linear scan.**

### Mitigations

- **XXE protections** (see Tampering).
- **PKIX path length limits** — `PKIXParameters` default `maxPathLength` is enforced.
- **Structural OCSP parsing** — iterating `BasicOCSPResp.getResponses()` is bounded by the response size; the library matches on `SerialNumber` equality only.
- **No `Runtime.exec`, no `ObjectInputStream`**. The library has no deserialisation surface.

### Residual risks

- **No request size limit in the library.** Callers (Spring MVC `AttestationController`) inherit whatever `server.tomcat.max-http-form-post-size` and body size limits the ambient configuration imposes. Default Spring Boot settings are reasonable (~2 MB); production deployments should review.
- **No rate limiting.** The library provides no throttling. A deployer fronting this with a rate-limiter filter closes the gap. The sibling gatekeeper repo acknowledges the same.

---

## Elevation of privilege

### Assets at risk

- **Authorisation to have a signing certificate issued.** An unauthorised party must not be able to cause the issuance of a signing certificate for an identity they do not control.
- **Authorisation to assert HSM origin.** A SIGNING certificate must only issue when valid attestation is present.

### Attack vectors

1. Client submits a TRANSPORT certificate request and omits attestation, expecting a TRANSPORT path that bypasses HSM checks — but later presents the resulting certificate as if it were a SIGNING certificate (historical weakness: `requiresHsmAttestation()` was a client-driven heuristic).
2. Client submits a SIGNING request without attestation, attempting to get the certificate issued and fall back to "attestation added later".
3. `verifySignatoryRights` unconditionally returns `true` (historical weakness), letting anyone authorise issuance for anyone.
4. BankID-authenticated user tries to authorise issuance for a different organisation number than their mandate covers.

### Mitigations

- **Server-enforced certificate type.** `CertificateRequest.certificateType` is a required field. The server rejects SIGNING-without-attestation and TRANSPORT-with-attestation. Clients cannot flip type by omission.
- **Pluggable `SignatoryRightsVerifier`.** The placeholder `verifySignatoryRights` is removed. Default is `FailClosedSignatoryRightsVerifier` which returns UNKNOWN on every query; the `AttestationService` hard-fails SIGNING on UNKNOWN.
- **`MockAgreementRegistrySignatoryRightsVerifier`** provides the integration-shape reference for a real adapter; activation requires explicit `swish.signatory-rights.mode=mock-registry` opt-in.
- **BankID authentication** — `BankIdService.verify()` with XML-DSig verification binds the authorisation act to a specific personal number issued a specific BankID certificate. `AttestationService` forwards the authenticated identity to the signatory-rights verifier.
- **Structural OCSP cross-check** — ensures the BankID certificate was valid at authorisation time.

### Residual risks

- **Real `SignatoryRightsVerifier` is out of scope.** A production deployer must wire in a Swish / Bolagsverket-backed implementation. Until then SIGNING requests hard-fail, which is the correct conservative posture.
- **Compromised BankID issuance at the RA layer.** Out of scope for this library.
- **XML-DSig trust anchors for BankID.** The set of BankID CAs that `BankIdService` anchors is configured at build time (or loaded from classpath). Rotating anchors requires a deployer action.

---

## Supervisory loop integrity

### Assets at risk

- **Coupling between local verification and supervisory authorisation.** The four-phase flow (`verifyAndIssue`) is sound only if Phase 2 (gatekeeper.verify) is reached on every issuance, and Phase 4 (gatekeeper.confirm) is reached on every successful issuance.
- **Audit-record completeness.** A `Stage` enum value of `ISSUED_BUT_GATEKEEPER_CONFIRM_FAILED` represents a state where a certificate was created but the supervisory closure could not be recorded. The financial entity must treat this as an anomalous state rather than a normal completion.

### Attack vectors

1. The gatekeeper is unreachable, mis-configured, or returns malformed responses. A naive client could fall back to issuing without a receipt — silently degrading the supervisory guarantee.
2. The gatekeeper signs a verify-step receipt, but the confirm step fails (for example: the issuer-CA bundle on the gatekeeper side does not yet trust the issuing CA, or the public key the issuer used does not match the verify-step approval). A naive client could leave the certificate in the wild without any registry entry that links it back.
3. A confirm response is forged or intercepted — e.g. a man-in-the-middle returns a fabricated `loopClosed=true` envelope.
4. Replay of an old confirm response against a newly minted certificate.

### Mitigations

- **Default `swish.gatekeeper.mode=fail-closed`.** `FailClosedGatekeeperClient.verify(...)` throws `GatekeeperException` rather than returning a permissive default. A deployer who has not configured a gatekeeper URL cannot accidentally issue certificates without supervisory approval.
- **`Stage` enum on `IssuanceResponse`** — the post-issuance failure state `ISSUED_BUT_GATEKEEPER_CONFIRM_FAILED` is named explicitly. The financial entity's incident-response runbook (out of code scope but flagged here) decides whether to revoke the issued certificate or to retry the confirm.
- **Confirm response cryptographically bound to the verify step.** The gatekeeper compares the public-key fingerprint of the submitted certificate against the one approved in Phase 2, and the gatekeeper-side issuer-CA validator (`IssuerCaValidator`) rejects certificates that do not chain to a trusted issuer CA. The local verifier additionally checks the `verificationId` returned in the confirm matches the one carried by the verify step.
- **HTTPS / mTLS in production.** `HttpGatekeeperClient` is run over TLS; if mTLS is configured at the Spring Boot client side, the gatekeeper authenticates the financial entity by client certificate.

### Residual risks

- **Confirm replay.** The gatekeeper does not currently issue a per-flow nonce that the confirm must echo. An attacker who already holds a verify-step approval and a freshly issued certificate could be denied — but a stale confirm response could be replayed by a man-in-the-middle within the validity of the underlying TLS session. This is a known GAP in the gatekeeper repo's `THREAT_MODEL.md` — Step-7 nonce binding.
- **Behaviour during partial-network outages.** A confirm-step failure that is purely transport-level (TCP reset, gateway 5xx) is indistinguishable at the client side from a substantive rejection. The deployer's runbook must default to revocation in any non-deterministic case.

---

## Receipt forgery

### Assets at risk

- **Trust the financial entity places in an `VerifyResponse`.** A receipt that the entity accepts as authoritative becomes the basis on which a signing certificate is then issued — both the issuance act and any subsequent supervisory inquiry rely on the receipt being genuine.
- **Trust the financial entity places in a confirm response.** Symmetrically.

### Attack vectors

1. An attacker produces a fabricated `VerifyResponse` with `compliant=true` and a valid-looking signature that does not chain to any registered gatekeeper key.
2. An attacker produces a receipt signed by a previously-trusted-but-now-retired gatekeeper key, hoping the financial entity has not yet rotated its trust registry.
3. An attacker tampers with a single field of an authentic receipt (e.g. flips `compliant=false` to `true`) and re-signs with a self-controlled key.
4. An attacker substitutes the canonicalisation logic at the financial-entity-side library boundary so that a different byte sequence is signed than the one verified.

### Mitigations

- **Local digest match.** The financial entity computes the canonical byte representation of the receipt locally (`ReceiptCanonicalizer.canonicalize(...)`) and compares against the receipt's signed bytes. The byte-format is locked by `WireFormatGoldenBytesTest` to a hardcoded golden literal that is identical in the gatekeeper repo. A code-level desynchronisation between the two repos breaks the test on both sides simultaneously.
- **Trusted-key registry.** `GatekeeperKeyRegistry` is populated from `swish.gatekeeper.trusted-keys` — a list of PEM-encoded gatekeeper certificates explicitly trusted by the financial entity. `ReceiptVerifier.verify(receipt)` resolves the certificate carried in the receipt against the registry by SHA-256 fingerprint; a receipt signed by a key outside the registry is rejected.
- **No blind acceptance.** Without both a successful local digest match and a successful registry-key lookup, `ReceiptVerifier.verify(...)` returns `false` and `AttestationService.verifyAndIssue` halts at Phase 2.
- **Constant-time comparisons** for fingerprints — `MessageDigest.isEqual(...)`.

### Residual risks

- **Trust-registry hygiene.** The financial entity must keep `swish.gatekeeper.trusted-keys` up to date with the gatekeeper's published key directory (`GET /v1/gatekeeper/keys`). Stale trust stores either reject legitimate receipts (operational-only impact) or, more dangerously, continue to trust a retired key past its retirement date.
- **Compromised registry contents.** If an attacker can write to the `swish.gatekeeper.trusted-keys` configuration source (Spring Cloud Config, secrets store, etc.), they can register an attacker-controlled key as trusted. This is an operational-environment concern outside the code; standard secrets-management hygiene applies.

---

## Gatekeeper key compromise

### Assets at risk

- **Cryptographic basis for accepting any past or future gatekeeper receipt.** If the operating NCA's gatekeeper signing key is compromised, an attacker can forge `VerifyResponse` envelopes that the financial entity's `ReceiptVerifier` would accept — until the trust registry is updated.

### Attack vectors

1. Theft of the gatekeeper's seal private key (operational compromise at the NCA side).
2. Cryptanalytic break of the signature algorithm.
3. Insider misuse at the NCA (a legitimate signer key is used to seal a receipt that the NCA's decision-making did not authorise).

### Mitigations

- **Retired-keys support in `GatekeeperKeyRegistry`.** The registry distinguishes active and retired keys. A key that the gatekeeper has retired can be marked as such on the financial entity side too, while still being honoured for receipts dated before the retirement (necessary for the DORA Article 28(6) 5-year retention window). After actual compromise — not retirement — the financial entity's incident response is to remove the compromised key from the registry **without** retroactive grandfathering: all receipts signed by it must be treated as suspect regardless of date, because the compromise window is generally not known.
- **Public key directory.** The gatekeeper exposes `GET /v1/gatekeeper/keys`, which returns the active and retired signing certificates with fingerprints. The financial entity's deployer can periodically reconcile its `swish.gatekeeper.trusted-keys` against this directory, and removes the compromised entry promptly when the NCA publishes a key-rotation notice.
- **Anchor publication.** The gatekeeper periodically publishes a signed audit-chain head via `GET /v1/gatekeeper/anchor`. A financial entity that retains anchor publications can detect retroactive log fabrication even after a key compromise — receipts signed by the compromised key but absent from the chain known at anchor time t0 are demonstrably forged.

### Residual risks

- **Pre-detection window.** Between the moment of compromise and the moment the NCA publishes a key-rotation notice, an attacker can mint plausible receipts. Standard PKI hygiene (HSM-protected seal key, multi-factor key-use authorisation, real-time alerting on signature counter mismatches) bounds the window.
- **Receipts already accepted.** Certificates that were already issued under a compromised receipt remain in operation until proactively revoked. The financial entity's revocation pipeline must be fast enough to catch this — out of code scope, but flagged here.
- **Cloud-anchored vs Yubico/Securosys-anchored receipts.** The placeholder cloud-HSM attestation trust anchor in this reference does not change the gatekeeper key compromise picture — the gatekeeper's own signing key is structurally separate from the trust anchors used to validate attestation chains.

---

## Summary of residual risks

| Category | Residual risk | Scope |
| -------- | ------------- | ----- |
| Spoofing | Vendor root CA or BankID CA compromise | Out of code scope; inherent to PKI |
| Spoofing | Clock skew | Mitigated operationally (HW baseline §3.1), not in code |
| Tampering | OCSP response freshness enforcement | Caller responsibility |
| Repudiation | Log tamper-evidence | Out of this repo; in gatekeeper or SIEM |
| Information disclosure | Masked PNR still partly identifying | Acceptable operational trade-off |
| DoS | No in-library rate limiting | Deployer responsibility |
| Elevation | Real signatory-rights adapter not shipped | Explicit GAP; fail-closed default protects production |
| Supervisory loop | Confirm replay without nonce binding | GAP — flagged in gatekeeper repo's `THREAT_MODEL.md`; close with server-issued nonce |
| Supervisory loop | `ISSUED_BUT_GATEKEEPER_CONFIRM_FAILED` revocation policy | Deployer runbook responsibility |
| Receipt forgery | Stale `swish.gatekeeper.trusted-keys` configuration | Operational hygiene; reconcile periodically against `GET /v1/gatekeeper/keys` |
| Gatekeeper key | Pre-detection compromise window | Bounded by NCA's seal-key operational controls; out of code scope |
| Gatekeeper key | Already-issued certificates under a compromised receipt | Deployer revocation pipeline responsibility |

The **central claim** this code has to sustain for Article 1 and Article 2 is that verification is deterministic and independent of institutional trust. Every attack vector above either (a) is mitigated inside the library with the pinned-root + PKIX + XXE-protection construction, or (b) is an acknowledged residual risk that does not weaken the central claim — it delimits it. The fail-closed test suite (`[HSM]/src/test/java/.../TestPki`-based tests) is the mechanical falsification harness.
