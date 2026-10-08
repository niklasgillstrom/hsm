# Changelog — hsm

Versions before 1.4.0 have no entry here; their history is recorded in
`PEER_REVIEW_GUIDE.md` ("Version 1.3.0 — what changed and what to verify" and
"Corrections after documentation-versus-code review").

## 1.6.0 (2026-10-08)

### Security

- **Customer and technical supplier sent to the gatekeeper.** The verify
  request carried the customer's organisation number as `supplierIdentifier`
  and the BankID relying party's name as `supplierName`: via a technical
  supplier the two named different parties, and the supplier's identity was
  not recorded. hsm now sends the customer (`customerOrganisationNumber`,
  `customerSwishNumber`) and, when the caller's transport certificate is a
  technical supplier's (987…), the supplier (`supplierIdentifier` = O,
  `supplierNumber` = CN, `supplierName` only when the supplier is the BankID
  relying party). A customer calling with its own 123 certificate has no
  supplier fields. The receipt must echo all four (`REJECTED_RECEIPT_MISMATCH`
  otherwise). **Breaking:** receipt canonical form `v3`, in step with
  gatekeeper 1.6.0. `ReceiptVerifier` still verifies a retained `v2` receipt
  (1.4.0–1.5.0), but only one without the new fields, so they cannot be added
  to an old receipt unsigned. Tests: `AttestationServiceGatekeeperFlowTest`
  (`theGatekeeperIsToldTheCustomerAndTheTechnicalSupplier`,
  `aCustomerCallingItselfHasNoTechnicalSupplier`,
  `aSupplierThatIsNotTheRelyingPartyIsNotGivenItsName`, three new receipt
  mismatch cases), `ReceiptVerifierAlgorithmTest`
  (`aReceiptSignedBefore160StaysVerifiable`,
  `partyFieldsCannotBeAddedToAReceiptSignedBefore160`), golden bytes.
- **Weak CSR signature algorithms could be configured.** The README said
  SHA-1 and MD5 are refused, but `swish.key-policy.allowed-csr-signature-algorithms`
  accepted them when an operator listed them. Start-up now fails for any
  SHA-1 or MD2/MD5 entry (`KeyPolicyTest.weakCsrSignatureAlgorithmsCannotBeConfigured`).
- **Mutation testing with PIT** (`mvn -Ppit test-compile org.pitest:pitest-maven:mutationCoverage`,
  PIT 1.30.0 with the JUnit 5 plugin 1.2.3, which runs under JUnit 6.0.3).
  First run over all of hsm: 2 094 mutations, 76 % killed, test strength
  88 %, 298 without coverage; now 2 074 of 2 074 detected (2 070 killed,
  4 timed out), and the profile fails below 100 %. New tests cover the
  vendor dispatch, early refusals and every issuance stage of
  `AttestationService` (with mocked collaborators), BankID parsing, OCSP
  shapes, Id registration, certificate extraction and the PKIX path, the
  mock gatekeeper and issuance clients, the receipt verifier's refusals, the
  HTTP client, the policies' start-up warnings and refusal wording, and the
  size filter's counting stream. Redundant constructs whose mutants no test
  could kill were removed, not suppressed (see `PEER_REVIEW_GUIDE.md`,
  Mutation testing); `SwishCaService`, referred to by nothing, is removed. Two survivors of the earlier manual run are
  now killed: ignoring the XML-DSig result
  (`BankIdSignatureVerificationTest.payloadAlteredAfterSigningIsRejected`)
  and bypassing the gatekeeper key registry
  (`ReceiptVerifierAlgorithmTest.aReceiptSignedByAKeyOutsideTheRegistryIsRefused`).
- **Build:** swagger-ui 5.33.1; Lombok 1.18.48 for the dependency as for the
  annotation processor (Spring Boot manages 1.18.46).
- **The caller's transport certificate is bound to the request.** The API is
  called with mTLS, with the company's transport certificate (its Swish
  number, 123…) or the technical supplier's (987…). Until now the service did
  not look at that certificate, so any holder of a valid transport
  certificate could submit a request for another company. `CallerPolicy` now
  requires a 123 certificate's CN to be the request's Swish number and its O
  the request's organisation number, and a 987 certificate's O to be the
  BankID relying party; anything else, or no certificate, is refused
  (`CALLER_NOT_BOUND`, `CALLER_CERTIFICATE_MISSING`). On by default
  (`swish.caller-binding=required`); the `dev` profile sets `off`. The
  certificate's chain and validity remain the TLS layer's job
  (`server.ssl.client-auth=need`, Swish CA in the trust store).
  Tests: `CallerPolicyTest` (12), `AttestationServiceTransportTest.callerBinding`,
  `AttestationControllerCallerTest` (2) and `CallerCertificateWiringTest`,
  which makes real mTLS calls. Each fails when the certificate is not passed
  from the TLS layer to the service or not checked there (mutants: controller
  passes null, service skips the check, `verifyAndIssue` drops the caller,
  controller takes the last certificate of the chain instead of the leaf).

- **Build:** Jackson 3.1.7 and 2.21.7 instead of the 3.1.5 and 2.21.5 that
  Spring Boot 4.1.1 manages (CVE-2026-83557, listed as fixed in 3.1.6 and
  2.21.6); `project.build.outputTimestamp`, so the same commit builds to a
  byte-identical jar (two builds of railgate compared: different hashes
  without it, identical with it); and the OWASP Dependency-Check scan moved
  to the `owasp` profile (`mvn -Powasp verify`), so a build without
  network access or NVD key can run the tests.

- **TRANSPORT requests require confirmed signatory rights.** Until now a
  TRANSPORT request whose signatory could not be confirmed (UNKNOWN or
  UNAUTHORISED) was issued with a warning. With the default
  `FailClosedSignatoryRightsVerifier`, which answers UNKNOWN to every query,
  any BankID holder could therefore obtain a TRANSPORT certificate for any
  organisation and Swish number. The signatory check is now a hard error for
  every certificate type (`AttestationService.verify`).
- **TRANSPORT issuance has its own stage.** `verifyAndIssue` reported a
  TRANSPORT issuance, in which no gatekeeper takes part, as
  `VERIFIED_ISSUED_AND_CONFIRMED`, the stage that means the supervisory loop
  is closed. It is now `ISSUED_TRANSPORT_NOT_SUPERVISED`.
- Tests: `AttestationServiceTransportTest` (3 new, each failing before the
  change). `AttestationServiceRequestBindingTest` asserted that a TRANSPORT
  request was valid while signatory rights were UNKNOWN; it now confirms
  signatory rights with a stub, since it tests the request bindings only.
- **The retained receipt can be re-verified.** `IssuanceResponse.VerifyResponseSummary`,
  the audit record of the gatekeeper receipt, left out `confirmationNonce`,
  which is the third field of the signed v2 canonical form, and stored absent
  `keyProperties` / `doraCompliance` as `false` where the canonical form
  writes empty fields. The record therefore could not rebuild the signed
  bytes, and `ReceiptVerifier` rejected every retained receipt. The summary
  now carries the nonce and whether each sub-object was present, and
  `toVerifyResponse()` rebuilds the receipt for verification. Tests:
  `VerifyResponseSummaryTest` (2) and
  `AttestationServiceGatekeeperFlowTest.retainedReceiptReverifiesFromTheAuditRecord`,
  all three failing before the change. Retention itself is still the
  deployer's: nothing in this repository persists the `IssuanceResponse`.
- **Key and CSR signature-algorithm policy.** No key size, curve or
  algorithm was checked: RSA-512, RSA-1024, secp192r1 and a CSR signed with
  MD5withRSA were all issued for. `KeyPolicy` now refuses any key not in
  `swish.key-policy.allowed-keys` (default `RSA-4096`) and any CSR signature
  algorithm not in `swish.key-policy.allowed-csr-signature-algorithms`
  (default SHA-256, SHA-384 or SHA-512 with RSA), with `KEY_POLICY_VIOLATION`.
  Both real fixtures (RSA-4096, `sha256WithRSAEncryption`) pass the default.
  Tests: `KeyPolicyTest` (7) and
  `AttestationServiceTransportTest.defaultKeyPolicyRefusesRsa2048`. Tests that
  use synthetic RSA-2048 keys name `RSA-2048` in their policy explicitly.
- **What the BankID signatory saw, and who asked.** The request binding sits
  in `usrNonVisibleData`, which the signatory never sees, and neither the
  BankID relying party nor `usrVisibleData` was checked. Any company with a
  BankID agreement could have a signatory approve a harmless text with the
  binding hidden, and the signature authorised a certificate.
  `BankIdConsentPolicy` now requires the relying party's organisation number
  (`srvInfo`) to be in `swish.bankid.allowed-relying-parties` (empty by
  default, refusing everything) and the visible text to contain the request's
  organisation number and Swish number. Tests: `BankIdConsentPolicyTest` (9)
  and two in `AttestationServiceTransportTest`. The existing service tests
  signed "Jag godkanner avtalet"; they now sign a mandate text naming the
  organisation and Swish number.
- **The confirm response is verified.** Its integrity rested on TLS alone:
  any party able to answer the confirm call could return `loopClosed=true`
  with the right `verificationId`, and the issuance was recorded as
  `VERIFIED_ISSUED_AND_CONFIRMED`. A null `publicKeyMatch` was accepted for an
  issued certificate, and the key the gatekeeper confirmed was never compared
  with the CSR. Gatekeeper 1.6.0 signs the response (`ConfirmationCanonicalizer`,
  form `c1`, golden literal shared in `ConfirmationCanonicalizerGoldenBytesTest`);
  `ReceiptVerifier.verifyConfirmation` checks it against the trusted gatekeeper
  keys, and `AttestationService` now also requires `publicKeyMatch=true` and
  the confirmed `actualPublicKeyFingerprint` to equal the CSR's. **Requires
  gatekeeper 1.6.0**: an unsigned response from an older gatekeeper now ends
  in `ISSUED_BUT_CONFIRM_NOT_CLOSED`. `MockGatekeeperClient` signs its
  responses. `IssuanceConfirmResponse.RegistryStatus` gains
  `ANOMALY_NONCE_MISMATCH`, which the gatekeeper already used. Tests: the
  golden test (2) and two in `AttestationServiceGatekeeperFlowTest`
  (`unsignedConfirmIsNotAClosedLoop`, `signedConfirmForAnotherKeyIsNotAClosedLoop`),
  both failing against the previous check.

- **BankID signatures had no age limit and could be reused.** The OCSP
  response's `producedAt`, `thisUpdate` and the signing time were never
  compared with the current time, and BankID's responses carry no
  `nextUpdate` (verified in the production example in `README.md`), so a
  signature and its response were accepted at any age and for any number
  of issuances. `producedAt` must now be at most
  `swish.bankid.max-signature-age` (default `PT15M`) old, and neither it
  nor `thisUpdate` may be more than 5 minutes in the future; and a
  signature authorises as many issuances as its mandate states (below),
  after which an issuance is refused (`REJECTED_BANKID_ALREADY_USED`,
  closing that gatekeeper verification as not issued). Tests:
  `BankIdSignatureVerificationTest` (`staleProducedAtIsRejected`,
  `futureProducedAtOrThisUpdateIsRejected`, `aSignatureIsConsumedCountTimes`,
  `consumptionIsAtomic`, `consumedSignaturesExpire` and others),
  `AttestationServiceTransportTest.aBankIdSignatureIsUsedCountTimes`,
  `AttestationServiceGatekeeperFlowTest.aOneCertificateMandateAuthorisesOneSigningIssuance`.
- **OCSP entries were matched on serial number alone.** A serial number is
  unique only per CA; the entry must now also name the issuing CA by its
  name and key hashes (`sameSerialOtherIssuerIsRejected`).
- **The BankID binding did not fit the mandate.** The signatory approves a
  mandate for N certificates ("fyra (4) Swish-certifikat"), collected once;
  the technical supplier then makes one call per certificate and creates
  each CSR just before its call. `hsm-csr:v1` bound each signature to one
  CSR, so a signature could obtain certificates for one key only, but for
  that key without limit, and the count the signatory saw was never read.
  **Breaking:** `usrNonVisibleData` now carries
  `hsm-mandate:v1;org=…;swish=…;count=<1..99>`; the visible text must state
  the count as "(N)"; one signature authorises at most N issuances, with any
  CSRs. `hsm-csr:v1` strings are refused. Tests:
  `AttestationServiceRequestBindingTest` (`oneMandateCoversSeveralCsrs`,
  `mandateForAnotherNumberIsRejected`, `csrBoundBindingIsRejected`,
  `countNotInTheVisibleTextIsRejected`), `BankIdSignatureVerificationTest`
  (`malformedMandatesAreRejected`), `BankIdConsentPolicyTest.theCountMustBeStated`.

- **A gatekeeper receipt was checked for authenticity and key only.** A
  genuine, compliant receipt for the same key but another country,
  supplier or key purpose, or an old one, authorised issuance. The receipt
  must now be within 5 minutes of now, echo the country code, supplier
  identifier, key purpose and HSM vendor this request sent, and report key
  properties consistent with compliance; otherwise
  `REJECTED_RECEIPT_MISMATCH`. Tests:
  `AttestationServiceGatekeeperFlowTest.receiptFieldsMustMatchTheRequest`
  (twelve cases; with the previous code a receipt for another country was
  issued on), `receiptWithinTheLimitsIsAccepted`, `ReceiptMismatchTest`.
- **Receipt signatures were verified with SHA256withRSA only.** gatekeeper
  can sign with any `gatekeeper.signing.algorithm`; hsm now uses
  `swish.gatekeeper.signature-algorithm` (default SHA256withRSA, SHA-1 and
  MD5 refused) (`ReceiptVerifierAlgorithmTest`).
- **The gatekeeper link accepted plain HTTP, and mTLS could only be set
  JVM-wide.** `HttpGatekeeperClient` now refuses an `http://` URL unless
  `swish.gatekeeper.allow-insecure-http=true`, takes its TLS material from
  the SSL bundle named by `swish.gatekeeper.ssl-bundle`, follows no
  redirects, and quotes at most 512 characters of an error body on one
  line (`HttpGatekeeperClientTransportTest`). `THREAT_MODEL.md` and
  `INTEGRATION_GUIDE.md` described a Spring-side mTLS configuration that
  never reached the JDK client.
- All 29 guard mutants of the receipt and transport changes are killed.

- **No request size limit.** Spring Boot bounds form and multipart bodies,
  not JSON, so a request of any size was read in full; `THREAT_MODEL.md`
  said bodies were limited to about 2 MB. `RequestSizeLimitFilter` (as in
  gatekeeper and railgate) caps bodies at
  `swish.limits.max-http-request-size` (1 MB) and headers at 8 KB
  (`RequestSizeLimitFilterTest`, and `RequestSizeLimitWiringTest` on a
  running server).
- **One reading of the CSR.** CSRs were read in four places: the BankID
  binding hash stripped every PEM header and decoded what was left, the
  signature check read the first PEM block, and mock issuance knew only
  the `CERTIFICATE REQUEST` label. Two PEM blocks in one field were hashed
  together but only the first was verified, and a CSR labelled `NEW
  CERTIFICATE REQUEST` passed verification and failed at issuance. `Csrs`
  now accepts exactly one block (either label, the same at both ends) or
  bare base64, and every step uses its DER (`CsrsTest`,
  `MockIssuanceClientTest.aCsrWithTheNewCertificateRequestLabelIsIssued`).
- **`SecurosysVerifier.verifyChain` returned true for any input.** It is
  not called by the verification flow, but it is the interface's chain
  check; it now runs the same PKIX validation under the pinned root
  (`verifyChainValidatesAgainstThePinnedRoot`). The same fix is in
  gatekeeper.
- **The mock gatekeeper accepted a confirmation nonce more than once** and
  kept its approvals in two unsynchronised maps. It now spends the nonce
  atomically, as gatekeeper does (`MockGatekeeperClientConcurrencyTest`;
  with the previous code a nonce confirmed twice, and up to sixteen racing
  confirms succeeded).
- **Logging defaulted to DEBUG** in the shipped `application.yaml`, where
  `THREAT_MODEL.md` describes DEBUG as the operator's choice; it is INFO.
- **Dead code removed:** the superseded `witness` package and its test,
  which were empty stubs marked for deletion, and the unused
  `client.GatekeeperClient` component.
- **README examples** showed `bankIdUsrNonVisibleData` as a bare hash, which
  would be refused with `BANKID_NOT_BOUND_TO_REQUEST`; they now show the
  mandate string.

### Verifiers

- **Securosys key origin is read from the attestation.** The verifier never
  read `<private_key creation="...">`, and `AttestationService` reported
  `keyOrigin="generated"` for every Securosys key, inferring it from
  `never_extractable` and `always_sensitive`. Those are not origin
  attributes; a key created outside the HSM and imported with
  `extractable=false` was not excluded by them. The root element must now be
  `private_key` with `creation="generated"`, otherwise
  `SECUROSYS_KEY_NOT_GENERATED`; the reported `keyOrigin` is the attribute's
  value. Tests: three in `SecurosysVerifierTest` (the two rejections fail
  before the change), and `RealAttestationFixtureTest` now asserts the
  fixture's `keyOrigin` against `expected.json`, as `examples/README.md`
  already claimed it did.
- **Documented, not changed:** Securosys attestations signed with PSS
  (`CKM_SHA256_RSA_PKCS_PSS`, used in Securosys' own PKCS#11 example) are not
  supported and are rejected. The real fixture is PKCS#1 v1.5.
- **Azure and Google: Marvell parser rebuilt from the vendors' tools.** Both
  verifiers parsed a format of their own (2-byte tags, a public-key tag
  `0x0350`) that matches neither vendor's tool. `AzureHsmVerifier` read JSON
  fields that `az keyvault key get-attestation` does not write and took the
  public key from the JSON's JWK, which the HSM does not sign: a genuine
  attestation of one key, paired with the JWK of another, gave
  `publicKeyMatch=true`. The new `MarvellAttestation` ports Microsoft's
  MIT-licensed parser and validator (`Azure/azure-managed-hsm-key-attestation`:
  firmware 2.x and 3.x layouts, attribute numbers, signature schemes, Marvell
  roots) and Google's `verify_attestation_chains.py` (gzip, SHA-256 PKCS#1
  v1.5, owner chain under Hawksbill Root v1 prod). The key is bound
  through the RSA modulus inside the signed blob (the EKCV binding was
  added later in 1.6.0, see below); EXTRACTABLE must be false
  and NEVER_EXTRACTABLE and LOCAL true. Azure reads the real `az` JSON;
  Google also checks the owner chain and accepts gzip input.
- **Marvell roots updated.** The 2015 Marvell root expired 2025-11-16; the
  roots are now the two in Microsoft's validator: the reissued
  LiquidSecurity root (2024-2034, same key) and the LiquidSecurity 2 root.
- **Format gate.** No real Marvell attestation has been run through the
  parser. Until a real fixture is committed, both
  verifiers add `MARVELL_FORMAT_UNCONFIRMED` and never report a valid
  attestation.
- **Firmware 2.x signature.** Microsoft's validator compares only the
  trailing 32 bytes of the raw RSA result with the hash. That is accepted only
  for public exponents of at least 65537; under e = 3 a cube root modulo
  2^256 forges it.
- **Marvell's published format.** Marvell's "Software Key Attestation" page
  and `verify_pubkey.py` document the response layout (one attestation of a
  key pair carries a public- and a private-key object), `OBJ_ATTR_MODULUS`
  (`0x0120`), the KCV (`0x0173`, first 3 bytes of SHA-1 of the DER public
  key) and the EKCV (`0x1003`, SHA-256 of it; the page's prose says HKDF,
  which neither its example nor its script does). Both objects are read;
  `ulTotalSize` must be the response length; every object's key material
  must match the CSR key, and the private key must match through its own
  modulus or EKCV or through the public key in the same blob.
- Tests: `MarvellAttestationTest` (12, one with Marvell's published example
  values), `AzureHsmVerifierTest` (6, replacing 2), `GoogleCloudHsmVerifierTest`
  (8, replacing 2).
  `AzureHsmVerifierTest.jwkNamingTheCsrKeyIsNotABinding` fails on 1.5.0.
- **Physical Marvell LiquidSecurity HSMs as a fifth vendor (`MARVELL`).**
  The hardware behind Azure and Google signs its own key attestation when a
  key is generated. `MarvellHsmVerifier` checks the manufacturer chain
  (pinned Marvell roots → card → partition), the signature and the same key
  evidence as the cloud verifiers. Never valid until a real attestation
  confirms the format (`MARVELL_FORMAT_UNCONFIRMED`). Tests:
  `MarvellHsmVerifierTest` (5).
- **Thales Luna as a sixth vendor (`THALES`).** A Luna HSM issues a Public
  Key Confirmation (PKC) only for keys it generated and that cannot leave a
  Luna HSM (Thales documentation). `ThalesLunaVerifier` checks the PKC chain
  as Thales's MIT-licensed `luna-pkc-validator` does (signature, issuer, EKU
  per position, CA flag, validity) under the pinned Chrysalis-ITS Root key,
  and that the Proof of Origin key is the CSR key. Two published copies of
  the root (serials 804500000007 and 80450000000D) carry that key. Thales's
  own PKC and CSR test vector verifies, so this vendor is not behind a
  format gate. Tests: `ThalesLunaVerifierTest` (8; all five guard mutants
  are killed).
- **Crypto4A QASM as a seventh vendor (`CRYPTO4A`).** `Crypto4AVerifier`
  follows Crypto4A's attestation specification (C4A-302-0043): every
  signature block (ECDSA P-384 and HSS/LMS) must verify over the DER claims,
  carry the attestation EKU and chain to the pinned C4A_RCA key, as
  `spa-attest verify` checks them. The key's `key-spki` must be the CSR key
  and the same object must carry private-key class, `key-is-confined`,
  `key-is-hardware-generated` and `key-never-extracted`, plus
  `qasm-certified-production` and `attestation-keys-are-unique`. The PKI
  Consortium's published QASM message verifies, both signatures included.
  Its OIDs (`1.3.6.1.4.1.39901.6.2.x`) match Crypto4A's specification; the
  PKI Consortium page lists them one level too deep. Tests:
  `Crypto4AVerifierTest` (10; all eleven guard mutants are killed).
- **Fortanix DSM as an eighth vendor (`FORTANIX`).** `FortanixVerifier`
  follows Fortanix's "Verifying Key Attestation Statements": the Key
  Attestation Authority certificate by PKIX with Fortanix's attestation
  policy to the pinned Fortanix root, its EKU and Key Usage; the statement
  signed by the authority, naming it as issuer, with no unknown critical
  extension and a signing time within the authority's validity and not in
  the future; the statement's key must be the CSR key and carry
  `fortanixKeyGeneratedInDSM` and `fortanixKeyNeverExportable`. Validation
  happens at the signing time, as Fortanix prescribes for its one-month
  authority certificates. The sample in Fortanix's documentation verifies.
  Tests: `FortanixVerifierTest` (7; all twelve guard mutants are killed).
- **Entrust nShield as a ninth vendor (`ENTRUST`).** `NShieldVerifier`
  follows Entrust's "Verifying an attestation bundle": the warrant (DDDS)
  from the pinned KWARN-1 key through Delegation certificates to the
  module's KLF2 and ESN (WV1); the module state certificate under KLF2 with
  the warrant's ESN, the KML, HKNSO and the module key list, `knsopub`
  hashing to HKNSO and `hkm` in the list (MSCV1-5); the world binding
  certificate (plain or FIPS) under `knsopub` before `hkm` is trusted, and
  CertKREaKRAbKNSO when present (WBCV1-5); the key generation certificate
  under KML whose key hash is that of `pubkeydata` (KGCV1-2); the ACL read
  in full and refused on anything unrecognised, with Entrust's forbidden
  permissions refused, working blobs required under the trusted module key,
  and a security-officer-certified group or MakeArchiveBlob action marking
  the key recoverable, which is refused (the Administrator Card Set could
  then use the key: the human factor of Art. 9(3)(d)); `pubkeydata` must be
  the CSR key (CSRL1). Only `ModuleInformation` warrants are accepted:
  Entrust states that `FieldUpgradeModuleInformation` certificates depend on
  legacy DSA-1024 signatures, which NIST SP 800-131A no longer allows to be
  made. Entrust's two examples carry such warrants and are refused after
  their warrants verify under KWARN-1. Below the warrant, reissued under a
  test root with the real KLF2 and ESN, Entrust's softcard example verifies
  and its module-protected example is refused as recoverable and for
  UseAsBlobKey. Tests: `NShieldVerifierTest` (25, with Entrust's bundles and
  synthetic bundles from test keys, including the FIPS world binding, an
  ECDSA KML and an RSA-4096 key; all 75 guard mutants are killed).

## 1.5.0

**Deploy together with gatekeeper 1.5.0 and railgate 1.5.0.** The receipt wire
format is unchanged (`v2`, byte-identical to gatekeeper's; `WireFormatGoldenBytesTest`
is untouched). What couples the three releases is the confirm step: gatekeeper
1.5.0 stores the issued signing certificate that hsm sends at Step 7, and railgate
1.5.0 looks that certificate up by (certificate serial, issuer DN) at settlement.
Without the stored certificate settlement fails with `CERT_NOT_FOUND`.

A third pass, starting from the question 1.4.0 left open and then following the
production (`http`) path end to end instead of through the mock. Every defect
below was present in 1.4.0 and earlier; none is a regression.

- **Yubico capabilities were read in the wrong byte order.** `YubicoVerifier`
  folded the capabilities extension (1.3.6.1.4.1.41482.4.5) little-endian, so
  `capBytes[0]` supplied bits 0–7. Yubico's reference implementation reads the
  value big-endian: python-yubihsm `objects.py`, `_get_int`, is
  `int.from_bytes(..., "big")`, and `defs.py` puts `EXPORT_WRAPPED` at `1 << 12`
  and `EXPORTABLE_UNDER_WRAP` at `1 << 16`. Read little-endian, both flags were
  taken from the wrong bytes: a key carrying `EXPORTABLE_UNDER_WRAP`
  (`00 00 00 00 00 01 00 00`) or `EXPORT_WRAPPED` (`00 00 00 00 00 00 10 00`) was
  reported as not exportable. It survived review because the only real fixture
  (`examples/yubico/request.json`, `00 00 00 04 00 00 06 60`) has neither flag set
  and reads as "no export flags" in both byte orders, so the end-to-end test could
  not tell the two readings apart; 1.4.0 recorded the question instead of
  answering it. Read big-endian, the fixture decodes to `SIGN_PKCS`, `SIGN_PSS`,
  `DECRYPT_PKCS`, `DECRYPT_OAEP` and `SIGN_ATTESTATION_CERTIFICATE` — a coherent
  RSA key; read little-endian it decodes to template and cipher bits that make no
  sense for it. The fold is now `caps = (caps << 8) | (b & 0xFF)` in the
  package-private `YubicoVerifier.parseCapabilities`, and the `TODO` is gone.
  gatekeeper 1.5.0 carries the identical fix. Tests: `YubicoVerifierTest`
  `capabilitiesOfRealFixtureCarryNoExportFlags`,
  `capabilitiesBit16IsExportableUnderWrap`, `capabilitiesBit12IsExportWrapped`,
  and `exportableUnderWrapInAttestationCertificateIsRejected`, which runs a
  certificate carrying the extension through `verifyYubicoAttestation`.
- **A Yubico key that had been exported and re-imported passed the origin
  check.** The origin extension (1.3.6.1.4.1.41482.4.3) was accepted whenever
  `GENERATED` (0x01) was set. Yubico defines `IMPORTED_WRAPPED` (0x10) as "set in
  combination with GENERATED/IMPORTED", so an origin of 0x11 is a key generated on
  some device, exported under wrap and imported here — and `getKeyOrigin()`
  reported it as `generated`. It survived review because the flags were parsed
  correctly and only the decision read one of them. The origin is now accepted
  only when `GENERATED` is set and neither `IMPORTED` nor `IMPORTED_WRAPPED` is;
  `getKeyOrigin()` reports `imported_wrapped` or `imported` before `generated`.
  Tests: `YubicoVerifierTest.originGeneratedIsAccepted` (0x01) and
  `originGeneratedAndImportedWrappedIsRejected` (0x11).
- **The Test BankID root was trusted in every profile.** `BankIdService` pinned
  `Test BankID Root CA v1 Test` next to the production root unconditionally, so a
  production deployment accepted signatures chaining to BankID's test PKI, whose
  identities are issued for testing and say nothing about a real signatory. It
  survived review
  because 1.3.0 replaced a far worse anchor (whatever root the caller submitted)
  and the question at the time was which roots to pin, not in which profile. The
  test root is now trusted only when `swish.bankid.allow-test-root=true`; the
  default is `false`, and only `application-dev.yaml` sets it. Tests in
  `BankIdSignatureVerificationTest`: `testRootIsNotTrustedByDefault`,
  `testRootIsTrustedWhenAllowed` (fixture signature, fixture root in the test-root
  position) and `pinnedTestRootIsAnAnchorOnlyWhenAllowed`.
- **`HttpGatekeeperClient` could not read a single gatekeeper response.**
  `VerifyResponse`, its nested `KeyProperties` and `DoraCompliance`, and
  `IssuanceConfirmResponse` were `@Data @Builder` only. Lombok then generates a
  package-private all-args constructor and no creator Jackson can use, so every
  response from a real gatekeeper failed to deserialise and `mode=http` could
  never issue a SIGNING certificate — fail-closed, but not working. It survived
  review because every test used `MockGatekeeperClient`, which builds the objects
  directly and never touches JSON. All four types now carry `@NoArgsConstructor
  @AllArgsConstructor` alongside `@Builder`. Test:
  `HttpGatekeeperClientDeserializationTest`, which parses bodies shaped like
  gatekeeper's `VerificationResponse` and `IssuanceConfirmationResponse` with the
  client's own `ObjectMapper` (now package-private) and checks that the
  deserialised receipt still canonicalises to the `v2` golden string.
- **`swish.gatekeeper.trusted-keys` registered at most one certificate.**
  `GatekeeperKeyRegistry` split the value on `",-----END CERTIFICATE-----"`, a
  sequence that does not occur in real input. Newline-separated certificates (as
  the README documents) registered only the first one; comma-separated
  certificates (as INTEGRATION_GUIDE documents) failed startup. It survived review
  because every test either passed an empty value or registered the mock's
  certificate programmatically. Every
  `-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----` block is now extracted
  and registered, whatever separates them; a non-empty value with no block fails
  startup. Test: `GatekeeperKeyRegistryTest` (two generated certificates, both
  formats).
- **The verify request always said `SE`.** `AttestationService` hardcoded
  `countryCode("SE")` in the verify body while `HttpGatekeeperClient` put the
  configured `swish.gatekeeper.country-code` in the URL, so a non-Swedish
  deployment sent a body that contradicted its own path. It survived review
  because the default is `SE`. The configured value is now used for both. Test:
  `AttestationServiceGatekeeperFlowTest.verifyRequestCarriesTheConfiguredCountryCode`.
- **Step 7 carries the issued certificate — now asserted.** The confirm already
  sent the issued certificate PEM with `issued=true`; nothing tested it, and with
  gatekeeper 1.5.0 storing that certificate for railgate it is load-bearing.
  `AttestationServiceGatekeeperFlowTest.confirmCarriesTheIssuedCertificatePem`
  runs the full SIGNING flow on the real Yubico fixture and checks the PEM, its
  issuer DN and its public key.
- **`swish.gatekeeper.url` defaulted to `http://localhost:8443`.** The README
  documented the default as "unset (fail-closed)"; with the localhost default,
  `HttpGatekeeperClient`'s blank-URL guard could never fire. The default is now
  empty.

### Documentation

- `THREAT_MODEL.md`: the confirm response was described as "cryptographically
  bound" to the verify step; it is unsigned, and is checked, not bound. The
  residual-risk entry still described the Step-7 nonce as missing; it exists, and
  the residual risk is the unsigned response. `GatekeeperKeyRegistry` was
  described as distinguishing active and retired keys; it is a flat set, and the
  text now says so.
- `INTEGRATION_GUIDE.md`, `CROSS_REFERENCE.md` and `PEER_REVIEW_GUIDE.md` named
  methods that do not exist (`requestIssuance`, `issueCertificate`, `parseXml`,
  `verifyAttestedProperties`) and described `SwishCaService` as the mock CA with
  an `issue` method. `SwishCaService` exists, but it validates Getswish CA chains;
  the mock CA is `MockIssuanceClient` behind `IssuanceClient`. The names now match
  the code.
- `THREAT_MODEL.md` said that for the cloud HSMs "unverified-owner attestations
  are rejected". No owner anchor is bundled and no owner chain is checked, so
  nothing rejects an attestation for that reason; only the expired-Marvell-root
  gap is fail-closed. Corrected.
- `INTEGRATION_GUIDE.md` rated the Azure and Google verifiers production-trustable
  for the manufacturer chain, and `README.md` listed Azure without saying that
  `AzureHsmVerifier` always adds `AZURE_ATTRIBUTES_UNVERIFIED`, so no Azure
  attestation verifies. Both now say so, and that gatekeeper 1.5.0 never returns
  COMPLIANT for Google (`GOOGLE_KEY_ORIGIN_UNVERIFIED`). hsm's own
  `GoogleCloudHsmVerifier` still reports `keyOrigin=generated` for a
  non-extractable key; `keyOrigin` is informational here and does not decide
  validity. `PEER_REVIEW_GUIDE.md` said `SecurosysVerifier` loads its root from
  the classpath; it parses a text-block constant.
- `CROSS_REFERENCE.md`: the rows on vendor support (Art 1 §4.3, Art 2 §5.2 NFR5),
  the Step-7 nonce and the approval-registry journal are brought into line with
  gatekeeper 1.5.0, and the claim that the file is shipped identically in the
  three repositories is withdrawn — the copies differ.

### Dependencies

- BouncyCastle `bcprov-jdk18on` and `bcpkix-jdk18on` 1.86; Tomcat 11.0.26
  (override kept; the parent still manages 11.0.24); springdoc-openapi 3.1.1,
  which ships swagger-ui 5.32.14; `org.webjars:swagger-ui` pinned to 5.32.15.
- `dependency-check-maven` stays at 12.2.2, for the reason recorded under 1.4.0:
  13.0.0 treats an absent NVD API key as an invalid key of length 0
  (dependency-check/DependencyCheck#8715), and 13.0.0 is the latest release. The
  plugin runs in `verify`, so upgrading would break a keyless build.
- `maven-compiler-plugin` is not pinned in this `pom.xml`; the parent's version
  applies.

### Local end-to-end support

- **`MockIssuanceClient` can issue under a configured test CA.** It generated a fresh CA key pair in memory at every start-up and never exported it, so no gatekeeper could be configured to trust the certificates it issued: a local run of the full flow ended Step 7 in `ANOMALY_PUBLIC_KEY_MISMATCH` because gatekeeper's issuer-CA check had nothing to anchor to. The new optional properties `swish.issuance.mock.ca-keystore`, `swish.issuance.mock.ca-keystore-password` and `swish.issuance.mock.ca-alias` load the CA key and certificate from a PKCS12 keystore; without them the behaviour is unchanged. The mock remains not-for-production. Tests: `MockIssuanceClientTest` (4). Used by the local end-to-end harness in the gatekeeper repository (`gatekeeper/e2e`).

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
