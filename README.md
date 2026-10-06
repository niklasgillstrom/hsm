# HSM Attestation Reference Implementation for Swish

Reference implementation for verification of HSM attestation in Swish certificate requests according to DORA/Cybersecurity Act.

## Documentation map

| Document | Audience | Purpose |
| --- | --- | --- |
| `README.md` (this file) | Everyone | Architecture, flow, supported vendors, build instructions |
| `INTEGRATION_GUIDE.md` | FE systems / integration engineer | How to wire this pattern into the FE's existing certificate-issuance pipeline: what's reusable, what adapters the FE must implement, configuration, audit/retention obligations, pre-production checklist |
| `PEER_REVIEW_GUIDE.md` | Academic peer reviewer | What the repo is and isn't, build-and-test, reproducible assertions, known limitations |
| `THREAT_MODEL.md` | Security reviewer, peer reviewer | Adversary model, mitigations, residual risks |
| `CROSS_REFERENCE.md` | Peer reviewer, deployer | Article-claim ↔ code-path mapping; honest GAP flags for what is and is not yet executable. Identical in both repositories. |

The companion repository `gatekeeper` carries the supervisory side and includes its own `DEPLOYMENT.md`, `SUPERVISORY_OPERATIONS.md` and `FORENSIC_INSPECTION.md` for the NCA-side runbook.

---

## Flow

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│   Client    │──────│  Attestation API │──────│  Getswish   │
│ CSR         │      │                  │      │     CA      │
│ BankID-sig  │      │ 1. Parse CSR     │      │             │
│ BankID-ocsp │      │ 2. Verify BankID │      │ Issue       │
│ OrgNo       │      │ 3. Verify HSM*   │      │ certificate │
│ SwishNo     │      │                  │      │             │
│ Attestation*│      │                  │      │             │
└─────────────┘      └──────────────────┘      └─────────────┘
                     * For signing certificates only
```

## Certificate types

| Type | Usage | HSM attestation |
|-----|------------|-----------------|
| TRANSPORT | mTLS to Swish API | No |
| SIGNING | Sign payouts | Yes (DORA requirement) |

## API

### POST /api/v1/attestation/verify

**Request:**
`bankIdOcspResponse` is **required** (since 1.4.0) — it supplies the certificate's revocation status at authorisation time and its `producedAt` becomes `bankIdSignatureTime` in the output. The BankID signature must additionally carry the canonical request binding in `usrNonVisibleData`; see "BankID request binding" below. The `certificateType` field is server-enforced: a `SIGNING` request is rejected if it does not carry attestation evidence; a `TRANSPORT` request is rejected if it does.
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIE...",
  "certificateType": "SIGNING",          // Required: SIGNING or TRANSPORT — enforced server-side
  "bankIdSignatureResponse": "PD94bWwgdmVyc2lvbj0iMS4wI...",
  "bankIdOcspResponse": "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",
  "organisationNumber": "5569741234",
  "swishNumber": "1234567890",
  "hsmVendor": "SECUROSYS",                             // Required for SIGNING; ignored for TRANSPORT
  "attestationData": "PD94bWwgdmVyc2lvbj0iMS4wI...",    // Required for SIGNING (not YubiHSM 2)
  "attestationSignature": "eywPlJWUEiLDnaq+NEAs4zB3...", // Required for SIGNING with SECUROSYS
  "attestationCertChain": ["-----BEGIN CERTIFICATE-----\n...", "-----BEGIN CERTIFICATE-----\n..."]
}
```

**Response for signing certificate:**
```json
{
  "valid": true,
  "certificateType": "SIGNING",
  "csrPublicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:22:df:6d:69:6d:ba:45:7f:59:55:4b:28:9b:65:08:92:f9:9b:3e:5c:c7:0d:e0:6f",
  "csrPublicKeyAlgorithm": "RSA",
  "attestedPublicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:22:df:6d:69:6d:ba:45:7f:59:55:4b:28:9b:65:08:92:f9:9b:3e:5c:c7:0d:e0:6f",
  "hsmVendor": "Securosys",
  "hsmModel": "Primus HSM",
  "hsmSerialNumber": "18000000",
  "publicKeyMatch": true,
  "attestationChainValid": true,
  "keyOrigin": "generated",
  "keyExportable": false,
  "bankIdSignatureValid": true,
  "bankIdCertificateChainValid": true,
  "bankIdCertificateCount": 3,
  "bankIdPersonalNumber": "19880807****",
  "bankIdName": "Test Testsson",
  "bankIdUsrVisibleData": "Bolagsnamn AB (556954-1234) ger härmed Teknisk leverantör AB (556964-1234) fullmakt att hämta fyra (4) Swish-certifikat för Swish-nummer 1234567890 kopplat till TL-nummer 9876543210.",
  "bankIdUsrNonVisibleData": "0b7ee6f76c72db770ed5c7fb2d01f9d6a5e9e3160fe9e4f37c678167d055af1e",
  "bankIdRelyingPartyName": "Teknisk leverantör AB",
  "bankIdRelyingPartyOrgNumber": "5569641234",
  "bankIdSignatureTime": "2026-01-15T12:00:00Z",
  "organisationNumber": "5569541234",
  "swishNumber": "1234567890",
  "authorizedSignatory": true,
  "errors": [],
  "warnings": []
}
```

**Response for transport certificate:**
```json
{
  "valid": true,
  "certificateType": "TRANSPORT",
  "csrPublicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:22:df:6d:69:6d:ba:45:7f:59:55:4b:28:9b:65:08:92:f9:9b:3e:5c:c7:0d:e0:6f",
  "csrPublicKeyAlgorithm": "RSA",
  "attestedPublicKeyFingerprint": null,
  "hsmVendor": null,
  "hsmModel": null,
  "hsmSerialNumber": null,
  "publicKeyMatch": false,
  "attestationChainValid": false,
  "keyOrigin": null,
  "keyExportable": true,
  "bankIdSignatureValid": true,
  "bankIdCertificateChainValid": true,
  "bankIdCertificateCount": 3,
  "bankIdPersonalNumber": "19880807****",
  "bankIdName": "Test Testsson",
  "bankIdUsrVisibleData": "Bolagsnamn AB (556954-1234) ger härmed Teknisk leverantör AB (556964-1234) fullmakt att hämta fyra (4) Swish-certifikat för Swish-nummer 1234567890 kopplat till TL-nummer 9876543210.",
  "bankIdUsrNonVisibleData": "0b7ee6f76c72db770ed5c7fb2d01f9d6a5e9e3160fe9e4f37c678167d055af1e",
  "bankIdRelyingPartyName": "Teknisk leverantör AB",
  "bankIdRelyingPartyOrgNumber": "5569641234",
  "bankIdSignatureTime": "2026-01-15T12:00:00Z",
  "organisationNumber": "5569541234",
  "swishNumber": "1234567890",
  "authorizedSignatory": true,
  "errors": [],
  "warnings": []
}
```

## Four-phase supervisory issuance flow

The reference flow speaks the gatekeeper's two-step supervisory protocol — `verify` followed by `confirm` — wrapped around a local pre-check and the actual certificate issuance. The financial entity's local verifier alone does not constitute auditable evidence under DORA Regulation (EU) 2022/2554 Article 6(10) — it is self-attested. A receipt signed by a structurally separate gatekeeper operated by (or on behalf of) the National Competent Authority — Finansinspektionen for Sweden, exercising powers conferred by EBA Regulation (EU) No 1093/2010 Articles 17 and 29 — is what makes the control falsifiable to the supervisor.

```
CertificateRequest (CSR + attestation + BankID + signatory rights)
      │
      ▼
Phase 1 — Local verification (AttestationService.verifyAndIssue, local pre-check)
      │   PKIX chain → pinned vendor root (Securosys / Yubico / Marvell)
      │   CSR public-key match against attested key
      │   BankID XML-DSig + OCSP (with XXE-protected DocumentBuilder)
      │   Signatory rights (pluggable; default is fail-closed)
      │
      ├─ invalid → IssuanceResponse{stage=LOCAL_VERIFICATION_FAILED}, no gatekeeper call
      │
      ▼
Phase 2 — Gatekeeper.verify (GatekeeperClient.verify, supervisory cross-check)
      │   POST VerifyRequest to NCA gatekeeper /v1/attestation/{countryCode}/verify
      │   Gatekeeper independently re-runs PKIX + attestation checks
      │   Gatekeeper signs the canonical bytes of VerifyResponse with its NCA key
      │   ReceiptVerifier checks signature against GatekeeperKeyRegistry
      │   Receipt's publicKeyFingerprint compared against the CSR's public key
      │
      ├─ non-compliant or signature invalid → stage=GATEKEEPER_REJECTED, no issuance
      ├─ receipt approves a different key → stage=REJECTED_RECEIPT_KEY_MISMATCH
      │
      ▼
Phase 3 — Issuance (IssuanceClient.issue, certificate produced)
      │   Mock implementation: signs leaf with in-process test CA
      │   Production: replace with adapter against Getswish CA
      │   IssuedCertificate carries verifyReceiptId binding it to the VerifyResponse
      │
      ├─ issuance failure → stage=ISSUANCE_FAILED, no confirm sent
      │
      ▼
Phase 4 — Gatekeeper.confirm (GatekeeperClient.confirm, supervisory closure)
      │   POST IssuanceConfirmRequest with the full signing certificate
      │   Gatekeeper validates the certificate against its trusted issuer-CA bundle
      │   Gatekeeper compares public-key fingerprint against the verify-step approval
      │   Confirm response carries loopClosed + publicKeyMatch + registryStatus
      │
      ├─ confirm fails after issuance → stage=ISSUED_BUT_GATEKEEPER_CONFIRM_FAILED
      │   (anomalous state — the certificate exists but the registry could not be
      │    closed; flagged for supervisory review, the certificate must be revoked
      │    unless the failure is shown to be transport-level only)
      ├─ confirm answered but does not close the loop (foreign verificationId,
      │   loopClosed=false, or a registryStatus other than VERIFIED_AND_ISSUED)
      │   → stage=ISSUED_BUT_CONFIRM_NOT_CLOSED (equally anomalous: here the
      │    supervisory record actively contradicts the issuance)
      │
      ▼
IssuanceResponse { stage, issued, verification, verifyReceipt, certificate, confirmResponse, errors }
```

`verifyAndIssue` returns an `IssuanceResponse` containing a `Stage` enum value that identifies precisely the phase at which the flow stopped. The whole `IssuanceResponse` is what the financial entity retains as the audit record for an issuance — it pairs the local verification evidence with the cryptographically signed supervisory authorisation and the supervisory closure.

`POST /api/v1/attestation/verifyAndIssue` is the HTTP endpoint that runs this flow. `POST /api/v1/attestation/verify` runs only Phase 1 and returns the bare `VerificationResponse` (kept for compatibility and for partial-flow inspection).

### Configuration

The gatekeeper and issuance components are pluggable via `application.yaml` / environment variables.

| Property | Reference default | Production value |
| -------- | ----------------- | ---------------- |
| `swish.gatekeeper.mode` | `fail-closed` | `http` |
| `swish.gatekeeper.url` | unset (fail-closed) | NCA gatekeeper URL, e.g. `https://dora-api.fi.se/v1/attestation` |
| `swish.gatekeeper.country-code` | `SE` | ISO 3166-1 alpha-2 of the operating NCA |
| `swish.gatekeeper.timeout-ms` | `5000` | site policy |
| `swish.gatekeeper.trusted-keys` | empty | newline- or comma-separated PEM certificates of authoritative gatekeeper signing keys, including retired keys still relevant for receipts within the DORA Article 28(6) 5-year retention window |
| `swish.bankid.allowed-relying-parties` | empty (every request refused, logged at `WARN`) | comma-separated organisation numbers of the BankID relying parties (the technical suppliers) whose BankID orders may authorise a request; any other is refused with `BANKID_RELYING_PARTY_NOT_ALLOWED` |
| `swish.key-policy.allowed-keys` | `RSA-4096` | comma-separated allow-list of `RSA-<bits>` / `EC-<curve>` (SEC names, e.g. `EC-secp384r1`); any other key is refused with `KEY_POLICY_VIOLATION` |
| `swish.key-policy.allowed-csr-signature-algorithms` | `SHA256withRSA,SHA384withRSA,SHA512withRSA` | comma-separated allow-list of JCA names for the CSR's own signature; SHA-1 and MD5 are refused |
| `swish.issuance.mode` | `mock` | replace with custom `IssuanceClient` against the Getswish CA |
| `swish.bankid.allow-test-root` | `false` (`true` in `application-dev.yaml`) | `false` — the `Test BankID Root CA v1 Test` anchor is trusted only when this is `true` |
| `swish.issuance.mock.ca-keystore` / `-password` / `ca-alias` | empty | only for local runs: PKCS12 keystore holding the mock issuing CA, so a local gatekeeper can trust it; empty means a fresh CA per start-up |

The three gatekeeper modes are:

- `fail-closed` — default. `FailClosedGatekeeperClient` throws `GatekeeperException` on every call. Production-safe when no gatekeeper URL has been configured: the issuance flow halts at Phase 2 rather than silently issuing certificates without supervisory approval.
- `mock` — `MockGatekeeperClient` runs an in-process gatekeeper using an ephemeral RSA key that is auto-registered with the local `GatekeeperKeyRegistry`. Suitable for demo / CI / peer review but never for production; the receipts are not cryptographically authoritative.
- `http` — `HttpGatekeeperClient` calls a real gatekeeper over HTTPS / mTLS. Receipts are verified against the trust registry populated from `swish.gatekeeper.trusted-keys`.

See `PEER_REVIEW_GUIDE.md` for the full list of reproducible assertions and the test breakdown that exercises each phase.

## Verification logic

The verification pipeline mixes two regulatory regimes that the reader should keep clearly separate:

- **DORA-mandated checks** — HSM attestation (Step 5) and server-enforced certificate type (Step 6). These satisfy DORA Regulation (EU) 2022/2554 Article 6(10) and 9(3)(d), 9(4)(d), 28(1)(a). Failing any of them is a regulatory non-compliance.
- **Integration-side checks** — BankID signature verification (Step 2), OCSP freshness (Step 3) and signatory-rights look-up (Step 4). BankID is the Swedish eID that Getswish AB uses for signatory authentication; technical providers integrating with Swish implement these checks because that is the operational precondition for certificate issuance ("har behörig person godkänt detta?"), not because DORA prescribes it. DORA does not specify how the requesting organisation's signatory is authenticated, and a future change in which eID Swish uses replaces this layer without affecting DORA compliance. eIDAS Regulation (EU) 910/2014 Articles 25 and 29 govern only the *legal effect* of the BankID signature when later presented as evidence; they do not make BankID itself a DORA control.

Numbered pipeline:

1. **CSR**: Parse PKCS#10 via BouncyCastle, **verify the CSR's own signature** under the public key it carries (proof of possession — a failure ends the request with `CSR_SIGNATURE_INVALID`), and extract the public key.
2. **BankID XML-DSig** *(integration-side, not DORA-mandated)*: Parse the BankID signature response with XXE-protected `DocumentBuilder`, verify the enveloping XML-DSig signature against the user certificate's public key (`javax.xml.crypto.dsig.XMLSignatureFactory`, DOM provider), and validate the certificate chain with PKIX `CertPathValidator`. The signature verification is what proves that `usrVisibleData` / `usrNonVisibleData` came from the BankID holder rather than being attacker-grafted onto a legitimate certificate chain. Required because Swish uses BankID for signatory authentication, not by DORA.
   The signed payload must also **bind the signature to this request** — see "BankID request binding" below (`BANKID_NOT_BOUND_TO_REQUEST`).
3. **OCSP (mandatory)** *(integration-side)*: Parse the OCSP response via BouncyCastle's `OCSPResp` / `BasicOCSPResp` / `SingleResp`, verify the response signature, verify the responder certificate under the public key of the CA that issued the user certificate (taken from the PKIX-validated path) and require Extended Key Usage `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9) and a current validity period, check `CertStatus` and the nonce binding, confirm that the `CertID.SerialNumber` matches the user certificate's serial, and read `producedAt` as the authoritative signing time. **`bankIdOcspResponse` is required** (`@NotBlank`): PKIX validation of the BankID chain runs with revocation checking disabled, so this response is the only evidence of the certificate's status at authorisation time. A request without it is rejected with `BANKID_OCSP_REQUIRED`.
4. **Signatory rights** *(integration-side)*: The pluggable `SignatoryRightsVerifier` checks whether the BankID-identified person is authorised to act as a signatory for the requested `organisationNumber` / `swishNumber`. Reference defaults:
   - `swish.signatory-rights.mode=fail-closed` — returns `UNKNOWN` for every query and logs `WARN`; every request fails, SIGNING and TRANSPORT alike.
   - `swish.signatory-rights.mode=mock-registry` — loads `(personalNumber, organisationNumber)` pairs from `classpath:signatory-rights.json` to demonstrate the integration shape; not authoritative.
   Production deployments must replace this with a Bolagsverket- or Swish-agreement-registry-backed implementation.
5. **HSM attestation** *(DORA-mandated; SIGNING only)*:
   - Verify that the public key in the CSR matches the attested key (constant-time comparison via `MessageDigest.isEqual`).
   - Verify the attestation certificate chain with PKIX `CertPathValidator` anchored at the pinned vendor root CA.
   - Verify the attestation signature. Securosys: a detached `SHA256withRSA` (PKCS#1 v1.5) signature over the raw XML bytes, which is what the real fixture carries. PSS-signed attestations (`CKM_SHA256_RSA_PKCS_PSS`, the mechanism in Securosys' own PKCS#11 example `hsm-api-examples/pkcs/c/src/attestation.cpp`) are not supported and are rejected. Cloud HSMs: see the vendor table below.
   - Verify key attributes: generated on the device and not exportable. Securosys: the root element must be `<private_key creation="generated">` (`SECUROSYS_KEY_NOT_GENERATED` otherwise) and `extractable=false`, `never_extractable=true`, `sensitive=true`, `always_sensitive=true`. Yubico: the origin and capabilities extensions.
6. **Server-enforced certificate type** *(DORA-mandated)*: SIGNING requests that do not carry attestation evidence are rejected. TRANSPORT requests that do carry attestation data are rejected as ambiguous.
7. **Issue certificate**: The Swish CA issues a transport or signing certificate matching the validated request type.

### BankID request binding

A BankID signature proves that a person signed *something*. To make it prove that they authorised *this* certificate request, the relying party puts a canonical binding string in `usrNonVisibleData` when creating the BankID sign order. BankID returns it inside the signed `bankIdSignedData` element, so it is covered by the XML-DSig Reference and cannot be substituted after signing.

The string, exactly (single line, no padding, no trailing separator):

```
hsm-csr:v1;org=<organisationNumber>;swish=<swishNumber>;csr-sha256=<lowercase hex SHA-256 over the CSR's DER encoding>
```

- `<organisationNumber>` and `<swishNumber>` are the values sent in the same request, verbatim.
- `<csr-sha256>` is SHA-256 over the **DER** encoding of the PKCS#10 request — the bytes inside the PEM armour, not the base64 text and not the PEM string. With OpenSSL: `openssl req -in request.csr -outform DER | sha256sum`.
- The string is UTF-8 encoded and base64 encoded once, into the BankID sign order's `userNonVisibleData` parameter. It comes back base64-encoded in the `usrNonVisibleData` element of the signature XML; `BankIdService` decodes that layer and compares the resulting string.

`AttestationService` recomputes the string from the request in hand and requires byte equality (`MessageDigest.isEqual`).

The binding sits in data the signatory never sees, so two further checks apply (`BankIdConsentPolicy`). The BankID relying party, whose organisation number is in `srvInfo` inside the signed data, must be listed in `swish.bankid.allowed-relying-parties` (`BANKID_RELYING_PARTY_NOT_ALLOWED`). And `usrVisibleData`, the text the signatory approved, must contain the request's organisation number (with or without hyphen) and Swish number (`BANKID_VISIBLE_TEXT_MISMATCH`). The wording is otherwise free; the mandate text in the response example above satisfies it. A missing `usrNonVisibleData`, or one belonging to a different organisation number, Swish number or CSR, is rejected with `BANKID_NOT_BOUND_TO_REQUEST`. Without this check, a signature legitimately collected for one request can be replayed with another request's CSR: the signature verifies, the personal number is genuine, and nothing else in the payload contradicts the swap.

Steps 2–4 reflect Swish's current operational integration (BankID for signatory authentication; signatory-rights look-up against an out-of-band registry); if Swish ever switches eID provider, only steps 2–4 change. Steps 5–6 are fixed by DORA and cannot be substituted regardless of any integration-side change.

## Supported HSM vendors

| Vendor | Status | Request format |
|--------|--------|----------------|
| Securosys Primus | ✅ | `attestationData` (XML), `attestationSignature`, `attestationCertChain` |
| Yubico YubiHSM 2 | ✅ | `attestationCertChain` |
| Azure Managed HSM | ⚠️ | `attestationData`: the JSON from `az keyvault key get-attestation` (whole, or its `attributes` or `attributes.attestation` object). Marvell chain under the pinned Marvell roots, both attestations signed by the partition certificate, key attributes and RSA modulus read from the signed blobs (`MarvellAttestation`). Never valid until a real attestation confirms the format (`MARVELL_FORMAT_UNCONFIRMED`). |
| Google Cloud HSM | ⚠️ | `attestationData` (base64 of `attestation.dat`, gzip or decompressed), `attestationCertChain`. Marvell chain and Google owner chain (Hawksbill Root v1 prod), both pinned; key attributes and RSA modulus read from the signed blob. Never valid until a real attestation confirms the format (`MARVELL_FORMAT_UNCONFIRMED`). |
| Marvell LiquidSecurity | ⚠️ | `attestationData` (base64 of `attest.dat`, produced when the key is generated), `attestationCertChain` (partition and card certificates). Marvell chain under the pinned Marvell roots, key attributes and RSA modulus or EKCV read from the signed blob. Never valid until a real attestation confirms the format (`MARVELL_FORMAT_UNCONFIRMED`). |
| Thales Luna | ✅ | `attestationData` (base64 of the DER Public Key Confirmation from `cmu getpkc`). PKC chain (Proof of Origin, Device Authentication, Hardware Origin, Mfg Integrity) under the pinned Chrysalis-ITS Root key; the Proof of Origin certificate's key must be the CSR key. Verified against Thales's own test vector (`src/test/resources/vendor-fixtures/thales-luna`). |
| AWS CloudHSM | ❌ | Lacks per-key attestation |


### Yubico YubiHSM 2

A YubiHSM 2 attestation chain has **three** certificates that together reach the pinned Yubico root CA:

1. **Per-key attestation cert** (the leaf) — produced when the client requests attestation for a specific key. Subject example: `CN=YubiHSM Attestation id:0x0024`. Issued by the device's own factory attestation CA.
2. **Per-device factory attestation cert** — pre-loaded as opaque object ID 0 on every YubiHSM 2. Subject example: `CN=YubiHSM Attestation (20783176)` where the number is the device serial. Issued by a Yubico Sub-CA.
3. **Sub-CA cert** — the intermediate. Subject example: `CN=Yubico YubiHSM 6742036 Sub-CA`. Issued by the pinned Yubico root.

The verifier pins only the root; the client must bundle all three lower certs in `attestationCertChain`. PKIX builds the chain leaf → factory CA → Sub-CA → pinned root and rejects on any break.

```bash
# 1. Request attestation for a specific key in the HSM. This produces the
#    per-key attestation certificate (the leaf). Exact command depends on
#    your YubiHSM tooling; below is the yubihsm-shell form.
yubihsm-shell -a sign-attestation-certificate \
              --attestation-id <key-id> --outformat PEM > attestation.pem

# 2. Fetch the per-device factory attestation certificate (opaque object ID 0).
yubihsm-shell -a get-opaque -i 0 --outformat PEM > device-ca.pem

# 3. Read the Authority Key Identifier of device-ca.pem to identify which
#    Yubico Sub-CA signed it. Yubico publishes one PEM per Sub-CA SKI.
openssl x509 -in device-ca.pem -noout -text | grep -A1 "Authority Key Identifier"
# → e.g. keyid:E4:5D:A5:F3:61:B0:91:B3:0D:8F:2C:6F:A0:40:DB:6F:EF:57:91:8E

# 4. Download the matching Sub-CA from Yubico (filename = SKI without colons).
curl -O https://developers.yubico.com/YubiHSM2/Concepts/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem
```

Request:
```json
{
  "hsmVendor": "YUBICO",
  "attestationCertChain": [
    "<content from attestation.pem>",
    "<content from device-ca.pem>",
    "<content from E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem>"
  ],
  ...
}
```

The Yubico root CA is *not* sent in the request — it is pinned in `YubicoVerifier` (SHA-256 `09:4A:3A:C4:93:C2:BD:CD:65:A5:4B:DF:40:19:0F:52:BB:03:F7:15:63:97:A3:FC:69:D8:AA:9A:39:2F:B7:24`). A complete real-world example payload is bundled at `examples/yubico/request.json`; the integration test in `RealAttestationFixtureTest` exercises that fixture.

## Azure Managed HSM

The client must:
```bash
az keyvault key get-attestation --hsm-name contoso --name mykey --file attestation.json
```

Request:
```json
{
  "hsmVendor": "AZURE",
  "attestationData": "<content from attestation.json>",
  ...
}
```

### Google Cloud HSM

The client must:
```bash
# 1. Download attestation and certificate chain
gcloud kms keys versions describe 1 \
  --key mykey --keyring myring --location global \
  --attestation-file attestation.dat.gz

gcloud kms keys versions get-certificate-chain 1 \
  --key mykey --keyring myring --location global \
  --output-file certs.pem

# 2. Base64 encode for API calls (gzip or decompressed are both accepted)
base64 -w0 attestation.dat.gz > attestation.b64
```

Request:
```json
{
  "hsmVendor": "GOOGLE",
  "attestationData": "<content from attestation.b64>",
  "attestationCertChain": ["<content from certs.pem>"],
  ...
}
```

### Marvell LiquidSecurity

A physical Marvell LiquidSecurity HSM, the hardware behind Azure Managed HSM
and Google Cloud HSM, signs a key attestation when the key is generated
(Marvell: "When you create a key on a Marvell HSM, you can optionally request
an attestation statement"). A financial entity that wants to show DORA
Art. 9.3 d met requests it at generation and keeps `attest.dat` with the
partition and card certificates.

Request:
```json
{
  "hsmVendor": "MARVELL",
  "attestationData": "<base64 of attest.dat>",
  "attestationCertChain": ["<partition certificate PEM>", "<card certificate PEM>"],
  ...
}
```

### Thales Luna

A Luna HSM issues a Public Key Confirmation (PKC) for one of its key pairs
with `cmu getpkc`. Thales: "A Luna HSM will issue confirmations only for
private keys that were created by a Luna cryptographic module and that can
never exist outside the security perimeter of a Luna HSM", and `cmu getpkc`
"works with non-extractable keys only". The PKC has no attribute list; that
the HSM issued it is the evidence.

Request:
```json
{
  "hsmVendor": "THALES",
  "attestationData": "<base64 of the DER PKC (.p7b)>",
  ...
}
```

## Prerequisites

```bash
brew install openjdk@21
sudo ln -sfn $(brew --prefix openjdk@21)/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk-21.jdk
export JAVA_HOME=/Library/Java/JavaVirtualMachines/openjdk-21.jdk/Contents/Home
java -version
```

```bash
mvn dependency:resolve
```

## Build and run

Install extensions in VSCode or setup your dev environment for Java and Spring Boot:

```bash
vscjava.vscode-java-pack
vmware.vscode-boot-dev-pack
```

```bash
mvn clean package
java -jar target/hsm-1.5.0.jar
```

**Swagger UI** is off in every profile except `dev` (`application-dev.yaml`); the
OpenAPI document and the UI have no run-time function and are kept out of the
deployed surface. Locally:

```bash
java -jar target/hsm-1.5.0.jar --spring.profiles.active=dev
# http://localhost:8080/swagger-ui.html   http://localhost:8080/v3/api-docs
```

## Production

Production deployment requires, beyond the reference configuration shipped here:

- **HSM manufacturer root CAs**:
  - **Securosys Primus** (`SecurosysVerifier`) — real vendor-issued root.
  - **Yubico YubiHSM** (`YubicoVerifier`) — real vendor-issued root, sourced from `https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem`. SHA-256 fingerprint `09:4A:3A:C4:93:C2:BD:CD:65:A5:4B:DF:40:19:0F:52:BB:03:F7:15:63:97:A3:FC:69:D8:AA:9A:39:2F:B7:24`. Operators should re-verify the fingerprint against an authoritative Yubico source.
  - **Azure Managed HSM** (`AzureHsmVerifier`) and **Google Cloud HSM** (`GoogleCloudHsmVerifier`) share `MarvellAttestation`, which pins the two Marvell roots in Microsoft's validator (MIT, `Azure/azure-managed-hsm-key-attestation`): the LiquidSecurity root reissued 2024-07-25 to 2034-07-23 with the same key as the 2015 root pinned before (SHA-256 `23:01:43:DF:00:E0:B4:52:74:3E:06:8A:5B:3F:C0:8D:F8:F0:6C:EF:C4:85:4E:A6:27:AE:B7:EB:D7:0E:E2:F4`) and the LiquidSecurity 2 root (SHA-256 `17:64:4D:E0:D3:3B:C7:3B:2F:4E:F4:C2:0A:11:F6:C8:CC:1F:72:3A:4C:D8:3E:E6:00:36:1C:BB:24:D8:D2:E5`). Google's owner root "Hawksbill Root v1 prod" (SHA-256 `46:B5:FD:35:1D:56:A0:72:1C:A0:AF:CD:17:31:C0:F7:B7:4E:39:41:EB:81:8B:FD:0E:C3:6E:29:DF:0D:E0:95`, valid to 2030-01-01) is copied from Google's `verify_attestation_chains.py`. Microsoft's validator also checks a partition chain, but it starts from a self-signed certificate taken from the submitted bundle, so it is not used. Operators should re-verify the Marvell roots against `marvell.com/.../liquid_security_certificate.zip`.
  - All pinned trust anchors — placeholder or real — are loaded fail-closed: if any cannot be parsed, the Spring Boot application refuses to start.
- **Signatory-rights registry**: replace the default `FailClosedSignatoryRightsVerifier` with a production `SignatoryRightsVerifier` adapter wired to an authoritative source (Swish agreement registry / Bolagsverket). Configure via `swish.signatory-rights.mode=<your-adapter>`. The fail-closed default will reject every SIGNING request until this is done.
- **Marvell attestation format**: `MarvellAttestation` follows Marvell's "LiquidSecurity HSM - Software Key Attestation" page (response layout with key-1/key-2 offsets, attribute numbers including `OBJ_ATTR_MODULUS` `0x0120`, KCV `0x0173` and EKCV `0x1003`, and a parsed RSA key-pair example), Marvell's MIT-licensed `verify_pubkey.py`, Microsoft's MIT-licensed parser and validator (byte offsets, firmware 2.x/3.x signatures) and Google's sample (gzip, SHA-256 PKCS#1 v1.5, owner chain). Neither cloud vendor's tool binds the attestation to a public key; here the private key must match the CSR key through its modulus or EKCV (SHA-256 of the DER public key, as `verify_pubkey.py` computes it and Marvell's example confirms), directly or through the public-key object in the same signed blob. Until a real Azure or Google attestation is committed as a fixture and `MarvellAttestation.FORMAT_CONFIRMED_BY_REAL_SAMPLE` is set, both verifiers add `MARVELL_FORMAT_UNCONFIRMED` and never report a valid attestation.
- **BankID XML-DSig integration test vectors**: the test suite builds its own PKI in-memory with BouncyCastle (see `src/test/java/.../testsupport/TestPki.java`) and asserts fail-closed behaviour. Before production, extend the suite with real BankID test vectors obtained from BankID's development environment.
- **Reproducibility**: run `mvn -B test` — all unit tests exercise the real PKIX `CertPathValidator` against the pinned root certificate of each verifier with no mocks. See `PEER_REVIEW_GUIDE.md` for the full list of reproducible assertions; the substantive-fix history is preserved in the Git commit log.

Known limitations are documented in `PEER_REVIEW_GUIDE.md` and `THREAT_MODEL.md` at the repository root.

## Companion repositories — the triadic system (since v1.2.0)

This repository is the financial-entity-side artefact of a three-component reference implementation. The triadic system together operationalises the data-minimised quadruple-triangulation model described in the companion academic articles (Article 1 §4.2, Article 2 §9.3):

- **hsm** — this repository, financial-entity-side HSM attestation verification core: <https://github.com/niklasgillstrom/hsm> ([10.5281/zenodo.19930310](https://doi.org/10.5281/zenodo.19930310), concept DOI)
- **gatekeeper** — NCA-operated certificate-issuance gate; from v1.1.0 also exposes `POST /api/v1/verify` for settlement-time signature verification: <https://github.com/niklasgillstrom/gatekeeper> ([10.5281/zenodo.19930395](https://doi.org/10.5281/zenodo.19930395), concept DOI)
- **railgate** — central-bank settlement-rail enforcement (RIX-INST in Sweden; generalisable to TIPS, FedNow, FPS, NPP): <https://github.com/niklasgillstrom/railgate> ([10.5281/zenodo.19952991](https://doi.org/10.5281/zenodo.19952991), concept DOI)

The hsm reference does not call gatekeeper's settlement-time verification endpoint directly — that path is exercised by railgate at the central-bank settlement layer. hsm interacts with gatekeeper at certificate issuance time via the two-step verify/confirm protocol (see "Four-phase supervisory issuance flow" above).

## How to cite

See `CITATION.cff` for citation metadata. GitHub renders a "Cite this repository" button from this file once the repo is public.

## License

MIT — Niklas Gillström <https://orcid.org/0009-0001-6485-4596>. Full text in `LICENSE`.
