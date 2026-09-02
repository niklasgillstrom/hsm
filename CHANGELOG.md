# Changelog — hsm

Versions before 1.4.0 have no entry here; their history is recorded in
`PEER_REVIEW_GUIDE.md` ("Version 1.3.0 — what changed and what to verify" and
"Corrections after documentation-versus-code review").

## 1.4.0

A second pass over the code against its own documentation, in the same spirit as
v1.3.0: each item below is a protection the repository described, or a property a
reader would reasonably assume from the code, that the code did not in fact
deliver. Every defect listed was present in 1.3.0 and in every earlier version —
none of them is a regression introduced after 1.3.0.

- **The CSR's own signature was never verified.** `AttestationService.verify`
  parsed the PKCS#10 request, took the public key out of it, and went on. A
  PKCS#10 request is self-signed by the private key belonging to the public key
  it carries; that signature is the only proof the requester holds the private
  half. Without checking it, a requester could submit any public key — including
  one whose private half belongs to somebody else, or one copied from an
  attestation captured elsewhere — and have a certificate issued for it, with the
  HSM-attestation checks passing because they compare the attestation against the
  submitted key rather than against a key the requester proved control of. The
  CSR signature is now verified with
  `csr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(csr.getSubjectPublicKeyInfo()))`
  and a failure ends the request with `CSR_SIGNATURE_INVALID`. Fail-closed: an
  error while attempting the check counts as a failed check. BouncyCastle is
  registered as a JCA provider in a static initialiser in `AttestationService`,
  next to the code that requires it.
- **The BankID signature was not bound to the request it authorised.**
  `BankIdService.verify` proved that a person signed *something*;
  `AttestationService` then used the resulting personal number without comparing
  the signed payload against the request in hand. `usrNonVisibleData` was read,
  returned in the response, and never checked. A BankID signature legitimately
  collected for one certificate request could therefore be presented with another
  request carrying a different CSR: the signature verifies, the personal number
  is genuine, and nothing contradicts the swap. THREAT_MODEL.md claimed the
  BankID step "binds the authorisation act" — it bound an identity, not an act to
  a request. v1.4.0 defines a canonical binding format in `BankIdService`:

  ```
  hsm-csr:v1;org=<organisationNumber>;swish=<swishNumber>;csr-sha256=<lowercase hex of SHA-256 over the CSR's DER encoding>
  ```

  The relying party sends this string (UTF-8, then base64) as
  `usrNonVisibleData` in the BankID sign order, so it travels inside the signed
  `bankIdSignedData` element and is covered by the XML-DSig Reference.
  `AttestationService` recomputes the expected string from the request and
  requires equality (`MessageDigest.isEqual`); a missing or differing payload is
  rejected with `BANKID_NOT_BOUND_TO_REQUEST`.
- **The gatekeeper receipt was checked for authenticity but not for subject.**
  `AttestationService.verifyAndIssue` verified the receipt's signature against
  the trusted-key registry and then issued, without ever comparing
  `VerifyResponse.publicKeyFingerprint` against the CSR's public key. An
  authentic receipt for some other key would have authorised issuance for this
  one. The fingerprints are now compared (canonical format: lowercase colon-hex
  SHA-256 over the SubjectPublicKeyInfo, the same format the gatekeeper's
  `util/Fingerprints` produces) and a mismatch is rejected with
  `RECEIPT_KEY_MISMATCH`. The format now has a single definition on this side too
  (`eu.gillstrom.hsm.util.Fingerprints`); `MockGatekeeperClient` previously
  emitted the colon-free `GatekeeperKeyRegistry.fingerprintHex` form in
  `publicKeyFingerprint`, which is a local registry key and not the wire format,
  and now emits the canonical form.
- **The confirm response was accepted without being read.** Any confirm response
  that did not throw produced stage `VERIFIED_ISSUED_AND_CONFIRMED`, including one
  carrying a different `verificationId`, `loopClosed=false`, or an
  `ANOMALY_*` registry status. THREAT_MODEL.md claimed "the local verifier
  additionally checks the `verificationId` returned in the confirm matches the one
  carried by the verify step"; it did not. The response is now required to echo
  the verify-step `verificationId`, to report `loopClosed=true`, and to end in
  `VERIFIED_AND_ISSUED`; anything else yields the new stage
  `ISSUED_BUT_CONFIRM_NOT_CLOSED` — the certificate exists, the supervisory
  record contradicts it, and the response says so instead of claiming closure.
  New stage `REJECTED_RECEIPT_KEY_MISMATCH` covers the pre-issuance rejection
  above.
- **OCSP was optional, and the responder was trusted on a string comparison.**
  `CertificateRequest.bankIdOcspResponse` had no validation constraint and
  `BankIdService.verify` treated an absent OCSP response as "skip this step" —
  while PKIX validation of the BankID chain runs with revocation checking
  disabled, so no revocation evidence was consulted at all in that path. The
  field is now `@NotBlank` and `verify` returns `valid=false` with
  `BANKID_OCSP_REQUIRED` when it is missing. Separately, the responder
  certificate was accepted on `signerCert.getIssuerX500Principal().equals(...)`
  plus a signature check *under the responder's own public key* — both of which a
  self-issued certificate carrying a copied issuer DN satisfies. The responder
  certificate is now (i) verified under the public key of the CA that issued the
  user certificate, taken from the PKIX-validated path
  (`OCSP_RESPONDER_NOT_ISSUED_BY_CA`, `OCSP_RESPONDER_CHAIN_INVALID` when that CA
  cannot be resolved), (ii) required to carry Extended Key Usage
  `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9, `OCSP_RESPONDER_EKU_MISSING`), and
  (iii) validity-checked. The existing nonce and `CertStatus` checks are
  unchanged.
- **Yubico capabilities extension: absent was read as satisfied.**
  `YubicoVerifier.extractYubicoAttributes` iterated `getNonCriticalExtensionOIDs()`
  only, and drew no conclusion from the capabilities extension
  (1.3.6.1.4.1.41482.4.5) being absent. The result object's exportability flags
  default to `false`, which reads downstream as "key cannot be exported" — an
  unparsed attribute presented as a satisfied one, the same defect class as the
  Azure/Google attribute handling fixed in 1.3.0. Both critical and non-critical
  extension OIDs are now read, and a missing capabilities extension produces
  `YUBICO_CAPABILITIES_MISSING: Capabilities attestation extension missing` and a
  non-compliant result.
- **Personal identity number written to the log on a DN parse failure.**
  `BankIdService.extractDnField` logged the whole distinguished name at WARN when
  `LdapName` failed to parse it. A BankID subject DN carries the signatory's
  personal identity number in `SERIALNUMBER` and their name in `CN`, so a
  malformed DN wrote both to the operational log — in a code path that is
  reachable by submitting a malformed certificate. The DN is no longer logged;
  the parse-failure message and the requested field name are.
- **No test loaded the Spring context.** Every test constructed its collaborators
  directly, so a wiring defect would first appear at deployment. New
  `ApplicationContextLoadsTest` (`@SpringBootTest`, `WebEnvironment.MOCK`,
  `swish.gatekeeper.mode=mock` + `swish.issuance.mode=mock` via
  `@TestPropertySource`) asserts only that the context comes up.
- Version bumped 1.3.0 → 1.4.0 in `pom.xml`. `THREAT_MODEL.md` corrected on three
  claims the code did not meet (authorisation-act binding, personal-number
  masking described as "first 6 digits" where the code preserves the first 8, and
  "bounded error enums" where errors are free-text strings); `README.md`
  documents the binding format and the mandatory OCSP response.

- **Receipt wire format moved to `v2` in lockstep with gatekeeper 1.4.0.** The
  gatekeeper now includes `confirmationNonce` in the signed canonical form (cell
  three, directly after `verificationId`), so that the nonce can no longer be
  altered in transit without breaking the receipt signature. `ReceiptCanonicalizer`
  here mirrors the change byte for byte; `WireFormatGoldenBytesTest` and
  `GatekeeperFlowTest` carry the same `v2` literal as the gatekeeper repo. An hsm
  1.3.0 verifier presented with a gatekeeper 1.4.0 receipt (or the reverse) will
  reject every signature — the two repos must be upgraded together.

### Configuration

- **OpenAPI document and Swagger UI are off unless the `dev` profile is active.** `springdoc.api-docs.enabled` and `springdoc.swagger-ui.enabled` are `false` in every shipped configuration file; the new `application-dev.yaml` turns them on for local use. Neither endpoint has a run-time function in this service, and swagger-ui is a third-party JavaScript application whose vulnerabilities (see Dependencies) would otherwise be part of the deployed surface. The OpenAPI path moves from `/api-docs` to springdoc's default `/v3/api-docs`.

### Dependencies

- Spring Boot parent 4.1.1 (Spring Framework 7, Spring Security 7), Lombok 1.18.48, springdoc-openapi 3.1.0, BouncyCastle 1.85 with `bcprov-jdk18on` 1.85.2.
- `org.webjars:swagger-ui` is pinned to 5.32.14. springdoc 3.1.0 ships 5.32.11, which bundles DOMPurify 3.4.12 (CVE-2026-75838). The earlier suppression for DOMPurify 3.3.2 (CVE-2026-41238/41239/41240) no longer matches anything and has been removed from `.owasp-suppressions.xml`; the file is now empty.
- `tomcat.version` is overridden to 11.0.25. Boot 4.1.1 manages 11.0.24, for which OWASP Dependency-Check reports eleven CVEs (CVE-2026-65182, -65183, -65637, -65905, -65927, -66299, -66422, -68525, -68569, -68763, -73180); all are listed as fixed in Tomcat 11.0.25 (2026-08-18). The override is to be removed once the parent manages 11.0.25 or later.
- `dependency-check-maven` stays at 12.2.2. 13.0.0 rejects an absent NVD API key as an invalid key of length 0 (jeremylong/DependencyCheck#8715), and this project is scanned without a key. The `<nvdApiKey>` configuration has been removed for the same reason.

### Known open question carried into 1.4.0

**Yubico capabilities bit order is unverified.**
`YubicoVerifier` folds the capabilities BIT STRING little-endian — `capBytes[0]`
supplies bits 0–7 — and reads `EXPORT_WRAPPED` at bit 12 and
`EXPORTABLE_UNDER_WRAP` at bit 16 from that. An ASN.1 BIT STRING is
conventionally read most-significant-bit first, which would place both flags at
different offsets, and Yubico's attestation documentation
(`developers.yubico.com/YubiHSM2/Concepts/Attestation.html`, capability table at
`developers.yubico.com/YubiHSM2/Concepts/Capability.html`) does not state the
encoding of extension 1.3.6.1.4.1.41482.4.5 unambiguously. The interpretation is
deliberately left unchanged in 1.4.0: swapping it without a documented ground
truth would trade one unverified reading for another. A `TODO` at the call site
records this. Resolve against Yubico's specification, or against a
device-produced attestation with a known capability set, before relying on the
exportability flags for a production compliance decision. Note that the
fail-closed change above narrows the exposure to the case where the extension is
present but decoded at the wrong offsets; a missing extension is now rejected
outright.
