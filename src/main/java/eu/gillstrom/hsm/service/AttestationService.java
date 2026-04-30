package eu.gillstrom.hsm.service;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import eu.gillstrom.hsm.gatekeeper.VerifyRequest;
import eu.gillstrom.hsm.gatekeeper.VerifyResponse;
import eu.gillstrom.hsm.gatekeeper.GatekeeperClient;
import eu.gillstrom.hsm.gatekeeper.GatekeeperException;
import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmRequest;
import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmResponse;
import eu.gillstrom.hsm.gatekeeper.ReceiptVerifier;
import eu.gillstrom.hsm.issuance.IssuanceClient;
import eu.gillstrom.hsm.issuance.IssuanceException;
import eu.gillstrom.hsm.issuance.IssuedCertificate;
import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.model.HsmVendor;
import eu.gillstrom.hsm.model.IssuanceResponse;
import eu.gillstrom.hsm.model.VerificationResponse;
import eu.gillstrom.hsm.model.VerificationResponse.CertificateType;
import eu.gillstrom.hsm.verification.AzureHsmVerifier;
import eu.gillstrom.hsm.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.hsm.verification.SecurosysVerifier;
import eu.gillstrom.hsm.verification.YubicoVerifier;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Service
public class AttestationService {

    private static final Logger log = LoggerFactory.getLogger(AttestationService.class);

    private final BankIdService bankIdService;
    private final SecurosysVerifier securosysVerifier;
    private final YubicoVerifier yubicoVerifier;
    private final AzureHsmVerifier azureVerifier;
    private final GoogleCloudHsmVerifier googleVerifier;
    private final SignatoryRightsVerifier signatoryRightsVerifier;
    private final GatekeeperClient gatekeeperClient;
    private final ReceiptVerifier receiptVerifier;
    private final IssuanceClient issuanceClient;

    public AttestationService(BankIdService bankIdService,
            SecurosysVerifier securosysVerifier,
            YubicoVerifier yubicoVerifier,
            AzureHsmVerifier azureVerifier,
            GoogleCloudHsmVerifier googleVerifier,
            SignatoryRightsVerifier signatoryRightsVerifier,
            GatekeeperClient gatekeeperClient,
            ReceiptVerifier receiptVerifier,
            IssuanceClient issuanceClient) {
        this.bankIdService = bankIdService;
        this.securosysVerifier = securosysVerifier;
        this.yubicoVerifier = yubicoVerifier;
        this.azureVerifier = azureVerifier;
        this.googleVerifier = googleVerifier;
        this.signatoryRightsVerifier = signatoryRightsVerifier;
        this.gatekeeperClient = gatekeeperClient;
        this.receiptVerifier = receiptVerifier;
        this.issuanceClient = issuanceClient;
    }

    /**
     * Four-phase supervisory issuance flow for SIGNING certificates:
     * <ol>
     *   <li><b>Local verification</b> — CSR / BankID / signatory rights /
     *       HSM-attestation re-checked locally. Required by DORA Article 6(10)
     *       which makes the financial entity fully responsible for the
     *       verification of compliance regardless of any external witness.</li>
     *   <li><b>Gatekeeper verify</b> — POST the canonical evidence to the
     *       operating NCA's gatekeeper (acting under EBA mandate Regulation
     *       (EU) No 1093/2010 Articles 17(6) and 29) and receive a
     *       cryptographically signed verification receipt. The receipt's
     *       signature is then verified locally against the trusted gatekeeper
     *       certificate registry — the financial entity does not blindly
     *       accept any signed receipt.</li>
     *   <li><b>Issuance</b> — only on a verified receipt; the issued
     *       certificate carries the gatekeeper's {@code verificationId} as an
     *       audit binding.</li>
     *   <li><b>Gatekeeper confirm</b> — POST the issued certificate (or a
     *       non-issuance notice) back to the gatekeeper so it can confirm
     *       that the public key in the issued certificate matches the one
     *       it approved at verify-time, closing the supervisory loop.</li>
     * </ol>
     *
     * <p>For TRANSPORT requests no gatekeeper step is required — the
     * certificate type is not subject to HSM-attestation control — so
     * gatekeeper.verify and gatekeeper.confirm are bypassed and issuance
     * proceeds directly.
     */
    public IssuanceResponse verifyAndIssue(CertificateRequest request) {
        // Phase 1: local verification.
        VerificationResponse local = verify(request);
        if (!local.isValid()) {
            return IssuanceResponse.rejectedLocal(local);
        }

        // TRANSPORT: not subject to HSM-attestation supervision; skip gatekeeper.
        if (local.getCertificateType() != CertificateType.SIGNING) {
            try {
                IssuedCertificate cert = issuanceClient.issue(request, null);
                return IssuanceResponse.issuedAndConfirmed(local, null, cert, null);
            } catch (IssuanceException e) {
                log.warn("Issuance failed for TRANSPORT request: {}", e.getMessage());
                return IssuanceResponse.rejectedIssuance(local, null, e.getMessage());
            }
        }

        // Phase 2: gatekeeper verify.
        VerifyRequest verifyRequest = buildVerifyRequest(request, local);
        VerifyResponse verifyReceipt;
        try {
            verifyReceipt = gatekeeperClient.verify(verifyRequest);
        } catch (GatekeeperException e) {
            log.warn("Gatekeeper verify call failed: {}", e.getMessage());
            return IssuanceResponse.rejectedGatekeeperVerify(local, e.getMessage());
        }

        if (verifyReceipt == null || !verifyReceipt.isCompliant()) {
            log.warn("Gatekeeper returned compliant=false (verificationId={}, errors={})",
                    verifyReceipt == null ? null : verifyReceipt.getVerificationId(),
                    verifyReceipt == null ? null : verifyReceipt.getErrors());
            return IssuanceResponse.rejectedNotCompliant(local, verifyReceipt);
        }

        if (!receiptVerifier.verify(verifyReceipt)) {
            log.warn("Gatekeeper verify-step receipt failed signature verification "
                    + "(verificationId={})", verifyReceipt.getVerificationId());
            return IssuanceResponse.rejectedReceiptInvalid(local, verifyReceipt);
        }

        // Phase 3: issuance.
        IssuedCertificate cert;
        try {
            cert = issuanceClient.issue(request, verifyReceipt.getVerificationId());
        } catch (IssuanceException e) {
            log.warn("Issuance failed after successful gatekeeper verify "
                    + "(verificationId={}): {}",
                    verifyReceipt.getVerificationId(), e.getMessage());
            // Best-effort: notify gatekeeper that we did NOT issue, so its
            // registry can move into VERIFIED_NOT_ISSUED rather than dangling.
            safeConfirmNonIssuance(verifyReceipt, e.getMessage(), request);
            return IssuanceResponse.rejectedIssuance(local, verifyReceipt, e.getMessage());
        }

        // Phase 4: gatekeeper confirm.
        IssuanceConfirmRequest confirmRequest = buildConfirmRequest(verifyReceipt, cert, request);
        IssuanceConfirmResponse confirmResponse;
        try {
            confirmResponse = gatekeeperClient.confirm(confirmRequest);
        } catch (GatekeeperException e) {
            // Anomalous — certificate is issued but the loop is open.
            log.warn("Gatekeeper confirm failed AFTER issuance (verificationId={}, "
                    + "issuanceId={}): {} — operators must follow up to close the loop",
                    verifyReceipt.getVerificationId(), cert.issuanceId(), e.getMessage());
            return IssuanceResponse.issuedButConfirmFailed(local, verifyReceipt, cert, e.getMessage());
        }

        return IssuanceResponse.issuedAndConfirmed(local, verifyReceipt, cert, confirmResponse);
    }

    /**
     * Build the gatekeeper verify request from the customer-facing
     * {@link CertificateRequest}. The wire format submits the attested
     * <em>public key</em> rather than the CSR — surrounding KYC metadata
     * (BankID, organisation/Swish numbers, subject DN) is intentionally
     * excluded; it is not part of the gatekeeper's mandate.
     */
    private static VerifyRequest buildVerifyRequest(CertificateRequest request,
            VerificationResponse local) {
        try {
            PublicKey pk = parseCsrPublicKey(request.getCsr());
            String publicKeyPem = toPublicKeyPem(pk);
            return VerifyRequest.builder()
                    .publicKey(publicKeyPem)
                    .hsmVendor(request.getHsmVendor())
                    .attestationData(request.getAttestationData())
                    .attestationSignature(request.getAttestationSignature())
                    .attestationCertChain(request.getAttestationCertChain())
                    .supplierIdentifier(request.getOrganisationNumber())
                    .supplierName(local == null ? null : local.getBankIdRelyingPartyName())
                    .keyPurpose(local == null ? null : ("Swish " + local.getCertificateType()))
                    .countryCode("SE")
                    .build();
        } catch (Exception e) {
            // CSR has already been parsed once locally, so this should not fire;
            // wrap in GatekeeperException so the caller gets a structured error.
            throw new GatekeeperException(
                    "Unable to extract attested public key from CSR for gatekeeper verify: "
                            + e.getMessage(), e);
        }
    }

    private static IssuanceConfirmRequest buildConfirmRequest(VerifyResponse verifyReceipt,
            IssuedCertificate cert, CertificateRequest request) {
        return IssuanceConfirmRequest.builder()
                .verificationId(verifyReceipt.getVerificationId())
                // Echo the gatekeeper's nonce back so it can verify this
                // confirm corresponds to the original verify call. Step-7
                // replay binding — without this, the gatekeeper rejects
                // the confirm with HTTP 400.
                .confirmationNonce(verifyReceipt.getConfirmationNonce())
                .issued(true)
                .signingCertificatePem(cert.certificatePem())
                .timestamp(DateTimeFormatter.ISO_INSTANT.format(java.time.Instant.now()))
                .nonIssuanceReason(null)
                .swishNumber(request.getSwishNumber())
                .organisationNumber(request.getOrganisationNumber())
                .build();
    }

    /**
     * Best-effort non-issuance notice — used after issuance fails locally so
     * the gatekeeper registry doesn't dangle. Failures here are swallowed at
     * WARN level: by the time we get here, the local issuance has already
     * failed and we want the original failure (not a secondary confirm error)
     * surfaced to the caller.
     */
    private void safeConfirmNonIssuance(VerifyResponse verifyReceipt, String reason,
            CertificateRequest request) {
        try {
            IssuanceConfirmRequest confirmRequest = IssuanceConfirmRequest.builder()
                    .verificationId(verifyReceipt.getVerificationId())
                    .confirmationNonce(verifyReceipt.getConfirmationNonce())
                    .issued(false)
                    .signingCertificatePem(null)
                    .timestamp(DateTimeFormatter.ISO_INSTANT.format(java.time.Instant.now()))
                    .nonIssuanceReason(reason)
                    .swishNumber(request.getSwishNumber())
                    .organisationNumber(request.getOrganisationNumber())
                    .build();
            gatekeeperClient.confirm(confirmRequest);
        } catch (GatekeeperException e) {
            log.warn("Best-effort non-issuance confirm to gatekeeper also failed "
                    + "(verificationId={}): {}", verifyReceipt.getVerificationId(), e.getMessage());
        }
    }

    private static PublicKey parseCsrPublicKey(String csrPem) throws Exception {
        String pem = csrPem.trim();
        if (!pem.contains("BEGIN")) {
            pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + csrPem
                    + "\n-----END CERTIFICATE REQUEST-----";
        }
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
            return new JcaPKCS10CertificationRequest(csr).getPublicKey();
        }
    }

    private static String toPublicKeyPem(PublicKey publicKey) {
        StringWriter w = new StringWriter();
        w.append("-----BEGIN PUBLIC KEY-----\n");
        w.append(Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(publicKey.getEncoded()));
        w.append("\n-----END PUBLIC KEY-----\n");
        return w.toString();
    }

    public VerificationResponse verify(CertificateRequest request) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        // Server enforces certificate type rather than inferring it from the
        // presence of attestation fields. A SIGNING request MUST carry
        // attestation evidence; a TRANSPORT request MUST NOT. Mismatches are
        // treated as validation errors so the issuing rules cannot be flipped
        // by a client that forgets (or deliberately omits) attestation fields.
        CertificateType certType = request.getCertificateType();
        if (certType == null) {
            errors.add("certificateType is required (SIGNING or TRANSPORT)");
            return buildErrorResponse(errors, CertificateType.TRANSPORT);
        }
        boolean hasAttestation = request.hasAttestationEvidence();
        if (certType == CertificateType.SIGNING && !hasAttestation) {
            errors.add("SIGNING requests require HSM attestation evidence "
                    + "(attestationData and/or attestationCertChain)");
            return buildErrorResponse(errors, certType);
        }
        if (certType == CertificateType.TRANSPORT && hasAttestation) {
            errors.add("TRANSPORT requests must not carry HSM attestation data — "
                    + "submit a SIGNING request if attestation is required");
            return buildErrorResponse(errors, certType);
        }

        // Parse CSR
        PublicKey csrPublicKey;
        String keyAlgorithm;
        try {
            PKCS10CertificationRequest csr = parseCsr(request.getCsr());
            csrPublicKey = extractPublicKey(csr);
            keyAlgorithm = csrPublicKey.getAlgorithm();
        } catch (Exception e) {
            errors.add("Invalid CSR: " + e.getMessage());
            return buildErrorResponse(errors, certType);
        }

        String csrFingerprint = fingerprint(csrPublicKey);

        // Verify BankID
        BankIdService.BankIdResult bankIdResult = bankIdService.verify(request.getBankIdSignatureResponse(),
                request.getBankIdOcspResponse());
        if (!bankIdResult.isValid()) {
            errors.add("BankID verification failed: " + bankIdResult.getError());
        }

        SignatoryRightsVerifier.Result signatoryResult = signatoryRightsVerifier.check(
                bankIdResult.getPersonalNumber(),
                request.getOrganisationNumber(),
                request.getSwishNumber());
        boolean authorizedSignatory = signatoryResult.isAuthorised();
        if (!authorizedSignatory) {
            // Fail-closed: any non-AUTHORISED outcome (UNAUTHORISED or UNKNOWN)
            // is a hard error for a signing-certificate request. Fall back to
            // warning-only for transport-certificate requests where signatory
            // authorisation is not strictly required.
            String message = "Signatory rights not confirmed (status="
                    + signatoryResult.status() + "): "
                    + (signatoryResult.reason() != null ? signatoryResult.reason() : "no reason given");
            if (certType == CertificateType.SIGNING) {
                errors.add(message);
            } else {
                warnings.add(message);
            }
        }

        // HSM attestation
        String attestedFingerprint = null;
        String hsmVendor = null;
        String hsmModel = null;
        String hsmSerial = null;
        String keyOrigin = null;
        boolean keyExportable = true;
        boolean publicKeyMatch = false;
        boolean attestationChainValid = false;

        if (certType == CertificateType.SIGNING) {
            HsmVendor vendor = detectVendor(request.getHsmVendor());
            if (vendor == null) {
                errors.add("hsmVendor is required for signing certificates");
            } else {
                hsmVendor = vendor.getVendorName();

                switch (vendor) {
                    case SECUROSYS -> {
                        var result = verifySecurosys(request, csrPublicKey);
                        publicKeyMatch = result.isPublicKeyMatch();
                        attestationChainValid = result.isChainValid();
                        hsmSerial = result.getHsmSerialNumber();
                        hsmModel = "Primus HSM";
                        if (result.getKeySize() != null) {
                            hsmModel += " (" + result.getAlgorithm() + " " + result.getKeySize() + ")";
                        }
                        keyOrigin = "generated"; // Securosys: never_extractable=true means generated
                        keyExportable = result.isExtractable();
                        if (!result.isValid()) {
                            errors.addAll(result.getErrors());
                        }
                        if (result.isPublicKeyMatch()) {
                            attestedFingerprint = csrFingerprint;
                        }
                    }
                    case YUBICO -> {
                        var result = verifyYubico(request, csrPublicKey);
                        publicKeyMatch = result.isPublicKeyMatch();
                        attestationChainValid = result.isChainValid();
                        hsmSerial = result.getDeviceSerial();
                        hsmModel = "YubiHSM 2";
                        keyOrigin = result.getKeyOrigin();
                        keyExportable = result.isKeyExportable();
                        if (!result.isValid()) {
                            errors.addAll(result.getErrors());
                        }
                        if (result.isPublicKeyMatch()) {
                            attestedFingerprint = csrFingerprint;
                        }
                    }
                    case AZURE -> {
                        var result = verifyAzure(request, csrPublicKey);
                        publicKeyMatch = result.isPublicKeyMatch();
                        attestationChainValid = result.isChainValid();
                        hsmSerial = result.getHsmPool();
                        hsmModel = "Azure Managed HSM";
                        keyOrigin = result.getKeyOrigin();
                        keyExportable = result.isExportable();
                        if (!result.isValid()) {
                            errors.addAll(result.getErrors());
                        }
                        if (result.isPublicKeyMatch()) {
                            attestedFingerprint = csrFingerprint;
                        }
                    }
                    case GOOGLE -> {
                        var result = verifyGoogle(request, csrPublicKey);
                        publicKeyMatch = result.isPublicKeyMatch();
                        attestationChainValid = result.isChainValid();
                        hsmSerial = result.getKeyId();
                        hsmModel = "Google Cloud HSM";
                        if (result.getKeySize() > 0) {
                            hsmModel += " (" + result.getKeyType() + " " + result.getKeySize() + ")";
                        }
                        keyOrigin = result.getKeyOrigin();
                        keyExportable = result.isExtractable();
                        if (!result.isValid()) {
                            errors.addAll(result.getErrors());
                        }
                        if (result.isPublicKeyMatch()) {
                            attestedFingerprint = csrFingerprint;
                        }
                    }
                    default -> errors.add("Vendor " + vendor + " not yet implemented");
                }
            }
        }

        boolean valid = errors.isEmpty() && bankIdResult.isValid();
        if (certType == CertificateType.SIGNING) {
            valid = valid && publicKeyMatch && attestationChainValid;
        }

        return VerificationResponse.builder()
                .valid(valid)
                .certificateType(certType)
                .csrPublicKeyFingerprint(csrFingerprint)
                .csrPublicKeyAlgorithm(keyAlgorithm)
                .attestedPublicKeyFingerprint(attestedFingerprint)
                .hsmVendor(hsmVendor)
                .hsmModel(hsmModel)
                .hsmSerialNumber(hsmSerial)
                .publicKeyMatch(publicKeyMatch)
                .attestationChainValid(attestationChainValid)
                .keyOrigin(keyOrigin)
                .keyExportable(keyExportable)
                .bankIdSignatureValid(bankIdResult.isValid())
                .bankIdCertificateChainValid(bankIdResult.isCertificateChainValid())
                .bankIdCertificateCount(bankIdResult.getCertificateCount())
                .bankIdPersonalNumber(maskPersonalNumber(bankIdResult.getPersonalNumber()))
                .bankIdName(bankIdResult.getName())
                .bankIdUsrVisibleData(bankIdResult.getUsrVisibleData())
                .bankIdUsrNonVisibleData(bankIdResult.getUsrNonVisibleData())
                .bankIdRelyingPartyName(bankIdResult.getRelyingPartyName())
                .bankIdRelyingPartyOrgNumber(bankIdResult.getRelyingPartyOrgNumber())
                .bankIdSignatureTime(bankIdResult.getSignatureTime())
                .organisationNumber(request.getOrganisationNumber())
                .swishNumber(request.getSwishNumber())
                .authorizedSignatory(authorizedSignatory)
                .errors(errors)
                .warnings(warnings)
                .build();
    }

    private SecurosysVerifier.SecurosysAttestationResult verifySecurosys(
            CertificateRequest request, PublicKey csrPublicKey) {

        if (request.getAttestationData() == null) {
            var result = new SecurosysVerifier.SecurosysAttestationResult();
            result.addError("attestationData (XML) is required for Securosys");
            return result;
        }
        if (request.getAttestationSignature() == null) {
            var result = new SecurosysVerifier.SecurosysAttestationResult();
            result.addError("attestationSignature is required for Securosys");
            return result;
        }
        if (request.getAttestationCertChain() == null || request.getAttestationCertChain().isEmpty()) {
            var result = new SecurosysVerifier.SecurosysAttestationResult();
            result.addError("attestationCertChain is required for Securosys");
            return result;
        }

        return securosysVerifier.verifySecurosysAttestation(
                request.getAttestationData(),
                request.getAttestationSignature(),
                request.getAttestationCertChain(),
                csrPublicKey);
    }

    private YubicoVerifier.YubicoAttestationResult verifyYubico(
            CertificateRequest request, PublicKey csrPublicKey) {

        if (request.getAttestationCertChain() == null || request.getAttestationCertChain().isEmpty()) {
            var result = new YubicoVerifier.YubicoAttestationResult();
            result.addError("attestationCertChain is required for Yubico");
            return result;
        }

        return yubicoVerifier.verifyYubicoAttestation(
                request.getAttestationCertChain(),
                csrPublicKey);
    }

    private AzureHsmVerifier.AzureAttestationResult verifyAzure(
            CertificateRequest request, PublicKey csrPublicKey) {

        if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
            var result = new AzureHsmVerifier.AzureAttestationResult();
            result.addError("attestationData (JSON from az keyvault key get-attestation) is required for Azure");
            return result;
        }

        return azureVerifier.verifyAzureAttestation(
                request.getAttestationData(),
                csrPublicKey);
    }

    private GoogleCloudHsmVerifier.GoogleAttestationResult verifyGoogle(
            CertificateRequest request, PublicKey csrPublicKey) {

        if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
            var result = new GoogleCloudHsmVerifier.GoogleAttestationResult();
            result.addError(
                    "attestationData (base64 of decompressed attestation.dat) is required for Google Cloud HSM");
            return result;
        }

        return googleVerifier.verifyGoogleAttestation(
                request.getAttestationData(),
                request.getAttestationCertChain(),
                csrPublicKey);
    }

    private HsmVendor detectVendor(String specified) {
        if (specified == null || specified.isBlank())
            return null;
        try {
            return HsmVendor.valueOf(specified.toUpperCase());
        } catch (IllegalArgumentException e) {
            // Unknown vendor token — callers handle a null return by falling
            // through to auto-detection or rejecting the request; no stack
            // trace is useful here, but a structured debug log helps operators
            // see what token clients are sending.
            log.debug("detectVendor: unknown HSM vendor token '{}'", specified);
            return null;
        }
    }

    private String maskPersonalNumber(String pnr) {
        if (pnr == null || pnr.length() < 12)
            return pnr;
        return pnr.substring(0, 8) + "****";
    }

    private PKCS10CertificationRequest parseCsr(String csrInput) throws Exception {
        String pem = csrInput.trim();
        if (!pem.contains("BEGIN")) {
            pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + csrInput + "\n-----END CERTIFICATE REQUEST-----";
        }
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            return (PKCS10CertificationRequest) parser.readObject();
        }
    }

    private PublicKey extractPublicKey(PKCS10CertificationRequest csr) throws Exception {
        var pkInfo = csr.getSubjectPublicKeyInfo();
        var keySpec = new java.security.spec.X509EncodedKeySpec(pkInfo.getEncoded());
        String algorithm = pkInfo.getAlgorithm().getAlgorithm().getId();
        String keyAlg = algorithm.startsWith("1.2.840.10045") ? "EC" : "RSA";
        return java.security.KeyFactory.getInstance(keyAlg).generatePublic(keySpec);
    }

    private String fingerprint(PublicKey key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(key.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x:", b & 0xff));
            }
            return sb.substring(0, sb.length() - 1);
        } catch (Exception e) {
            // SHA-256 is mandatory in every JRE (JCA guarantee), so this branch
            // should be unreachable — but if it ever fires we want a loud signal
            // rather than a silent "error" string.
            log.error("Unexpected SHA-256 fingerprint failure", e);
            return "error";
        }
    }

    private VerificationResponse buildErrorResponse(List<String> errors, CertificateType type) {
        return VerificationResponse.builder()
                .valid(false)
                .certificateType(type)
                .errors(errors)
                .warnings(Collections.emptyList())
                .build();
    }
}
