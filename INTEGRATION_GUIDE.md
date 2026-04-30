# FE integration guide — hsm

This document is for a financial entity (FE) integrating the gatekeeper-witnessed verification protocol into its existing certificate-issuance pipeline. In the Swish architecture the FE is GetSwish AB, but the same pattern applies to any FE that issues cryptographic certificates to technical providers (TLs) operating HSM-attested keys on the FE's behalf under DORA Regulation (EU) 2022/2554 Article 6(10) + Article 28(1)(a).

This repo is **not a deployable standalone service** in the way the sibling `gatekeeper` repo is. It is a **reference implementation of the FE-side integration pattern**: working code for each component the FE needs, plus interfaces where the FE plugs in adapters against its own internal infrastructure. The FE owns the certificate-issuance pipeline; this repo shows where to insert the gatekeeper-verify call, where to insert the gatekeeper-confirm call, what to retain afterwards, and what data the supervisor will triangulate against during inspection.

The audience is a **systems / integration engineer** at the FE who has been asked to wire DORA Article 6(10) verification into the FE's certificate-issuance pipeline. Operational responsibilities, regulatory framing and inspection procedures live in the sibling gatekeeper repo's `SUPERVISORY_OPERATIONS.md` and `FORENSIC_INSPECTION.md`.

---

## 1. What this repo provides

| Component | Role | Production-trustable as-is? |
| --- | --- | --- |
| `verification/SecurosysVerifier`, `verification/YubicoVerifier` | Vendor-specific HSM attestation verifiers; pin real vendor roots; PKIX-validated chain + signature + non-extractability check | Yes |
| `verification/AzureHsmVerifier`, `verification/GoogleCloudHsmVerifier` | Cloud-HSM verifiers; pin Marvell LiquidSecurity root | Yes (manufacturer chain), but cert expired 2025-11-16 — rotate before relying on post-expiry attestations; dual-chain owner-root validation not implemented (see verifier SECURITY NOTE) |
| `gatekeeper/GatekeeperClient` (interface) + `HttpGatekeeperClient` | The FE → NCA verify/confirm RPC, two-step protocol | Yes — `mode=http` against the NCA's published gatekeeper URL |
| `gatekeeper/ReceiptVerifier`, `gatekeeper/ReceiptCanonicalizer` | Validates the gatekeeper-signed receipt against the canonical bytes the FE submitted | Yes |
| `gatekeeper/GatekeeperKeyRegistry` | Trusted set of gatekeeper signing certificates | Yes — populate via `swish.gatekeeper.trusted-keys` |
| `service/AttestationService`, `controller/AttestationController` | End-to-end FE-side endpoint that takes CSR + attestation + BankID-signed mandate from a TL, runs the four-phase pipeline, returns issued cert | Reference flow only — adapt the wiring into the FE's own controller layer |
| `issuance/SwishCaService` | Mock CA that signs the CSR locally for the reference flow | **No** — replace with the FE's real CA integration |
| `service/SignatoryRightsVerifier` (interface) + `FailClosedSignatoryRightsVerifier` + `MockAgreementRegistrySignatoryRightsVerifier` | Validates that the BankID-signed mandate authorises the requesting TL | **No** for production — write a custom adapter against the FE's actual signatory-rights database |
| `service/BankIdService` | BankID signature verification (operational precondition for issuance) | Reference structure — adapt to the FE's actual BankID provider integration |

The four vendor verifiers, the gatekeeper-client + receipt-validation layer, and the verification-pipeline orchestration in `AttestationService` are usable directly. The CA, signatory-rights and BankID integrations are FE-specific and require adapter work.

---

## 2. Where to insert the gatekeeper protocol in the FE's pipeline

The four-phase supervisory issuance flow described in Gillström (in preparation, CMLJ and CLSR) is:

```
Phase 1 — Local verification (FE side)
  · Parse CSR + attestation submitted by TL
  · Run the vendor verifier (Securosys / Yubico / Azure / Google) → must pass
  · Verify BankID-signed mandate → must authorise this TL
  · Verify signatory rights against FE's own registry → must permit issuance

Phase 2 — gatekeeper.verify
  · Submit canonical attestation evidence to NCA's gatekeeper
  · Receive signed verification receipt with verificationId

Phase 3 — Issuance (FE side)
  · FE's CA signs the CSR
  · Persist the issuance record (CSR fingerprint, cert serial, verificationId,
    receipt PEM, BankID signature, attestation) for DORA Article 28(6)
    retention (5 years minimum)

Phase 4 — gatekeeper.confirm
  · Submit issued cert to NCA's gatekeeper
  · Gatekeeper verifies issued cert's public key matches the attested key
  · Gatekeeper logs the issuance closure in its hash-chained audit trail
```

In an FE that has an existing CSR-issuance pipeline, the integration points are:

- **Before** the FE's CA signs anything: insert Phase 1 (local verification) + Phase 2 (`gatekeeper.verify`). If either fails, abort issuance with a 4xx to the TL — the FE has not satisfied its Article 6(10) duty and a sanction-bearing breach would result if it proceeded.
- **After** the FE's CA returns a signed cert but before the cert is delivered to the TL: insert Phase 4 (`gatekeeper.confirm`). If `confirm` fails (e.g., gatekeeper rejects on public-key mismatch or registry anomaly), the FE must NOT deliver the cert; revoke it immediately.

The reference flow in `AttestationService.requestIssuance(...)` shows the orchestration in one place. The FE's production code can follow the same sequence or split it across services, as long as the four phases happen in order and the second/fourth complete before any production-trust signal (cert delivery to TL, registration in payment infrastructure, etc.) is emitted.

---

## 3. Adapters the FE must implement

### 3.1 `SignatoryRightsVerifier`

The shipped implementations are:

- `FailClosedSignatoryRightsVerifier` — production-safe default; rejects every query. Activated by `swish.signatory-rights.mode=fail-closed`.
- `MockAgreementRegistrySignatoryRightsVerifier` — reads a JSON config file. Activated by `swish.signatory-rights.mode=mock-registry`. Not authoritative.

Production: implement `SignatoryRightsVerifier` against the FE's authoritative source for "is this TL authorised to request a payment-signing cert under this organisation's agreement". For Swish, this is the GetSwish agreement registry, joined with Bolagsverket's authorised-signatory data. The adapter answers two questions per request:

1. Is the requesting organisation a current Swish-agreement holder?
2. Is the BankID-signed mandate's signatory currently registered as authorised to sign on that organisation's behalf?

Activate via `swish.signatory-rights.mode=<your-adapter>`. The default fail-closed mode means: **no production cert can be issued until this adapter is implemented**. That is intentional.

### 3.2 BankID integration

`BankIdService` ships as a verifier of BankID XML-DSig structure but does not connect to a live BankID provider. The FE's production deployment connects to the FE's contracted BankID provider (BankID Direkt API, or a re-seller). The adapter needs to:

- Establish the mandate as a currently-signed-by-authorised-signatory document at request time.
- Cache the BankID signature for the audit record.

The reference verifier validates the XML-DSig structure that comes back from a real BankID flow, so the cryptographic-validation layer is reusable; only the BankID-API integration is FE-specific.

### 3.3 Issuing CA (`IssuanceClient` / replacement for `SwishCaService`)

The mock `SwishCaService` signs CSRs with an ephemeral in-process test CA. Production: wire the FE's actual CA — common patterns are:

- **EJBCA** integration via REST/SOAP API.
- **Microsoft AD CS** via DCOM / certreq.
- **Custom in-house CA** — direct PKCS#11 access to the CA's signing HSM.

Replace `SwishCaService` with a class that takes the CSR + attested key fingerprint + verificationId and returns a signed cert. The verificationId must be retained alongside the cert in the FE's issuance record (DORA Article 28(6)).

---

## 4. Configuration — production environment variables

| Variable | Purpose | Production value |
| --- | --- | --- |
| `SWISH_GATEKEEPER_MODE` | Gatekeeper client backend | `http` |
| `SWISH_GATEKEEPER_URL` | NCA's published gatekeeper URL | `https://gatekeeper.fi.se:8443` (or jurisdictional equivalent) |
| `SWISH_GATEKEEPER_COUNTRY_CODE` | ISO-3166-1 alpha-2 jurisdiction code | `SE` (or relevant Member State) |
| `SWISH_GATEKEEPER_TIMEOUT_MS` | RPC timeout | `5000` (or higher for cross-border traffic) |
| `SWISH_GATEKEEPER_TRUSTED_KEYS` | Comma-separated PEMs of NCA gatekeeper signing certs that this FE accepts | The NCA's published certificate from `GET /v1/gatekeeper/keys` |
| `SWISH_SIGNATORY_RIGHTS_MODE` | Signatory-rights adapter | The FE's custom adapter name; **must not stay at `fail-closed`** in production |
| `SWISH_ISSUANCE_MODE` | CA backend | The FE's custom integration; **must not stay at `mock`** in production |

The mTLS client certificate the FE presents to the gatekeeper is configured at the HTTP-client level — the FE provides the keystore via the standard JVM TLS configuration (`-Djavax.net.ssl.keyStore=...`) or a Spring `RestClient` customizer.

---

## 5. Audit and retention obligations on the FE side

The FE's own audit record must cover what the gatekeeper's audit log does **not** cover:

| Datum | Where the FE must record it | Retention |
| --- | --- | --- |
| CSR submitted by TL (DER bytes) | FE's issuance record | DORA Article 28(6) — minimum 5 years |
| Attestation blob submitted by TL | FE's issuance record | Same |
| Local-verification result (per-vendor verifier) | FE's issuance record | Same |
| `verificationId` returned by gatekeeper | FE's issuance record | Same |
| Gatekeeper receipt PEM (signed) | FE's issuance record | Same |
| BankID-signed mandate | FE's issuance record | Same |
| Issued cert serial number | FE's issuance record | Same |
| `confirm` response from gatekeeper | FE's issuance record | Same |
| Cert revocation status over lifetime | FE's CRL / OCSP | Per the FE's CA policy |

Periodic data triangulation by the supervisor (described in the gatekeeper repo's `SUPERVISORY_OPERATIONS.md` §3.5) cross-references the FE's issuance record (this repository's audit data, not the gatekeeper's) with the gatekeeper's audit log and the issuing CA's CRL/OCSP. An issued cert without a matching `verificationId`+receipt in the FE's own record is a self-flagged Article 6(10) breach.

The FE retains these records under the FE's own retention infrastructure — separate from the gatekeeper's. There is no shared-storage assumption.

---

## 6. Operational concerns

### 6.1 Gatekeeper unavailability

If the gatekeeper RPC times out or returns an error during `verify`, the FE **must not** issue the cert — Article 6(10) verification has not completed. The reference `HttpGatekeeperClient` propagates the failure as `GatekeeperException`; `AttestationService` treats it as fatal. Production behaviour:

- Retry idempotently on transient network errors (the `verify` call is read-only with respect to gatekeeper state until the receipt is signed).
- If retry fails, return a 503 to the TL with a documented "verification temporarily unavailable" code; the TL retries later.
- Surface the failure to FE operations (alert pipeline). Persistent failures of the gatekeeper call ARE supervisable events under DORA Article 17 — a TL can complain to EBA that the FE is denying issuance because of NCA infrastructure.

### 6.2 `confirm`-call failure after a successful `verify` and `issue`

If the FE's CA signs the CSR but then `gatekeeper.confirm` fails (e.g., public-key mismatch detected by the gatekeeper, or transient network failure), the FE has issued a cert that is not closed in the gatekeeper's loop. Recovery procedure:

- **Public-key mismatch** — the issued cert's public key does not match the attested key. This is an integrity failure: revoke the cert immediately, alert FE operations, surface to NCA. The cert MUST NOT be delivered to the TL.
- **Transient network failure** — retry `confirm` indefinitely until acknowledged. Do not deliver the cert to the TL until `confirm` completes. The FE may retain the issued cert in escrow for a bounded window before treating the failure as terminal and revoking.

### 6.3 Receipt validation

Every receipt the FE receives from the gatekeeper must be validated against the trusted gatekeeper certificates in `swish.gatekeeper.trusted-keys` before being relied on. `ReceiptVerifier.verify(receipt)` does this — it (i) re-canonicalises the receipt body, (ii) verifies the gatekeeper signature against each trusted cert, (iii) returns the validated receipt for storage. If validation fails, treat as if the gatekeeper had returned an error — do NOT proceed with issuance.

The FE's trusted-keys list is updated whenever the NCA rotates its receipt-signing key. The NCA publishes both active and retired keys via `GET /v1/gatekeeper/keys`; the FE polls or watches this endpoint and refreshes `swish.gatekeeper.trusted-keys`. Receipts signed under retired keys remain verifiable for the 5-year retention horizon — the registry includes retired keys for that reason.

---

## 7. Compliance summary

The FE's integration of this pattern, properly wired, satisfies:

- **DORA Article 6(10)** — verification of compliance with cryptographic-control contractual provisions, evidenced by the gatekeeper-signed receipt.
- **DORA Article 28(1)(a)** — full responsibility irrespective of outsourcing, evidenced by the FE's own audit record covering CSR, attestation, BankID mandate and signed receipt.
- **DORA Article 28(6)** — 5-year retention of records relating to ICT third-party service providers, satisfied by the FE's record-keeping per Section 5.
- **DORA Article 30(2)(c)** — contractual provisions on authenticity, integrity and confidentiality of data, satisfied because the verifier rejects attestations that fail the cryptographic checks before issuance.

The FE's integration is **not** a substitute for a real CA, real BankID, or real signatory-rights infrastructure. Those remain FE-specific obligations that this reference does not deliver.

---

## 8. Pre-production checklist

Before the FE's first production traffic:

- [ ] `swish.gatekeeper.mode=http` and `swish.gatekeeper.url` points at the NCA's gatekeeper deployment
- [ ] `swish.gatekeeper.trusted-keys` is populated from the NCA's `GET /v1/gatekeeper/keys` and a refresh job is scheduled (weekly or per NCA policy)
- [ ] mTLS client certificate is provisioned and presented by the FE's HTTP client to the gatekeeper
- [ ] `swish.signatory-rights.mode` is set to the FE's custom adapter (NOT `fail-closed`, NOT `mock-registry`)
- [ ] `swish.issuance.mode` is set to the FE's custom CA integration (NOT `mock`)
- [ ] BankID integration is connected to the FE's contracted BankID provider
- [ ] FE's issuance record schema captures all the fields in Section 5 with at least 5-year retention
- [ ] `verify` failure returns 503 to the TL; alert pipeline is configured
- [ ] `confirm` failure recovery procedure is documented and exercised
- [ ] `ReceiptVerifier.verify(...)` is called on every received receipt and a failed verification is fatal
- [ ] Negative test: deliberate verification failure (corrupt attestation) results in a 4xx to the TL with no cert issuance

When every box is ticked, the FE-side integration is ready to accept TL traffic.
