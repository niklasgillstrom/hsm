package eu.gillstrom.hsm.model;

import lombok.Builder;
import lombok.Data;
import eu.gillstrom.hsm.gatekeeper.VerifyResponse;
import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmResponse;
import eu.gillstrom.hsm.issuance.IssuedCertificate;

import java.time.Instant;
import java.util.List;

/**
 * Outcome of {@code AttestationService.verifyAndIssue()}: pairs the local
 * verification result with the supervisory verify-step receipt, the issued
 * certificate, and the supervisory confirm-step response. The financial
 * entity should retain this whole structure as the audit record for the
 * issuance — it is the cryptographic and supervisory provenance trail
 * required to demonstrate compliance with DORA Regulation (EU) 2022/2554
 * Article 6(10).
 *
 * <p>The {@link Stage} enum records which phase produced the final outcome
 * so that operators can route per-stage failures to different escalation
 * paths (a failed gatekeeper.verify is a supervisory issue; a failed
 * gatekeeper.confirm is a recoverable anomaly because the certificate is
 * already issued).
 */
@Data
@Builder
public class IssuanceResponse {

    /** Phase that produced the final outcome. */
    public enum Stage {
        /**
         * Happy path: local verification, gatekeeper verify, issuance, and
         * gatekeeper confirm all succeeded. The supervisory loop is closed.
         */
        VERIFIED_ISSUED_AND_CONFIRMED,
        /** Local pre-checks (CSR / BankID / signatory rights / attestation) failed. */
        REJECTED_LOCAL_VERIFICATION,
        /** Gatekeeper verify call could not be completed (transport, configuration). */
        REJECTED_GATEKEEPER_VERIFY_FAILED,
        /** Gatekeeper verify completed but returned {@code compliant=false}. */
        REJECTED_GATEKEEPER_NOT_COMPLIANT,
        /**
         * Gatekeeper verify returned a receipt whose signature did not verify
         * under any trusted gatekeeper key in the local registry.
         */
        REJECTED_GATEKEEPER_RECEIPT_INVALID,
        /** Issuance step failed after a successful gatekeeper verify. */
        REJECTED_ISSUANCE_FAILED,
        /**
         * Anomalous: certificate was issued but the gatekeeper confirm call
         * failed. The supervisory loop is open. Operators must follow up.
         */
        ISSUED_BUT_GATEKEEPER_CONFIRM_FAILED
    }

    private Stage stage;
    private boolean issued;

    private VerificationResponse verification;

    /** Present once a gatekeeper verify-step receipt has been obtained. */
    private VerifyResponseSummary verifyReceipt;

    /** Present once a gatekeeper confirm response has been obtained. */
    private IssuanceConfirmResponseSummary confirmResponse;

    /** Present only if {@code issued == true}. */
    private IssuedCertificateSummary certificate;

    private List<String> errors;

    public static IssuanceResponse rejectedLocal(VerificationResponse v) {
        return IssuanceResponse.builder()
                .stage(Stage.REJECTED_LOCAL_VERIFICATION)
                .issued(false)
                .verification(v)
                .errors(v.getErrors())
                .build();
    }

    public static IssuanceResponse rejectedGatekeeperVerify(VerificationResponse v, String reason) {
        return IssuanceResponse.builder()
                .stage(Stage.REJECTED_GATEKEEPER_VERIFY_FAILED)
                .issued(false)
                .verification(v)
                .errors(List.of(reason))
                .build();
    }

    public static IssuanceResponse rejectedNotCompliant(VerificationResponse v, VerifyResponse receipt) {
        return IssuanceResponse.builder()
                .stage(Stage.REJECTED_GATEKEEPER_NOT_COMPLIANT)
                .issued(false)
                .verification(v)
                .verifyReceipt(VerifyResponseSummary.from(receipt))
                .errors(receipt == null || receipt.getErrors() == null
                        ? List.of("gatekeeper returned compliant=false")
                        : receipt.getErrors())
                .build();
    }

    public static IssuanceResponse rejectedReceiptInvalid(VerificationResponse v, VerifyResponse receipt) {
        return IssuanceResponse.builder()
                .stage(Stage.REJECTED_GATEKEEPER_RECEIPT_INVALID)
                .issued(false)
                .verification(v)
                .verifyReceipt(VerifyResponseSummary.from(receipt))
                .errors(List.of(
                        "Gatekeeper verify-step receipt did not verify against any trusted "
                                + "gatekeeper certificate in the local registry"))
                .build();
    }

    public static IssuanceResponse rejectedIssuance(VerificationResponse v,
            VerifyResponse receipt, String reason) {
        return IssuanceResponse.builder()
                .stage(Stage.REJECTED_ISSUANCE_FAILED)
                .issued(false)
                .verification(v)
                .verifyReceipt(receipt == null ? null : VerifyResponseSummary.from(receipt))
                .errors(List.of(reason))
                .build();
    }

    public static IssuanceResponse issuedButConfirmFailed(VerificationResponse v,
            VerifyResponse receipt, IssuedCertificate cert, String reason) {
        return IssuanceResponse.builder()
                .stage(Stage.ISSUED_BUT_GATEKEEPER_CONFIRM_FAILED)
                .issued(true)
                .verification(v)
                .verifyReceipt(VerifyResponseSummary.from(receipt))
                .certificate(IssuedCertificateSummary.from(cert))
                .errors(List.of(
                        "Certificate issued but gatekeeper confirm call failed: " + reason
                                + ". The supervisory loop is open; follow up with the operating NCA."))
                .build();
    }

    public static IssuanceResponse issuedAndConfirmed(VerificationResponse v,
            VerifyResponse receipt, IssuedCertificate cert, IssuanceConfirmResponse confirm) {
        return IssuanceResponse.builder()
                .stage(Stage.VERIFIED_ISSUED_AND_CONFIRMED)
                .issued(true)
                .verification(v)
                .verifyReceipt(VerifyResponseSummary.from(receipt))
                .confirmResponse(IssuanceConfirmResponseSummary.from(confirm))
                .certificate(IssuedCertificateSummary.from(cert))
                .errors(List.of())
                .build();
    }

    /**
     * Audit-friendly view of the gatekeeper verify-step receipt — carries
     * the full set of decision-relevant fields plus the base64 signature so
     * a downstream auditor can re-run signature verification independently.
     */
    @Data
    @Builder
    public static class VerifyResponseSummary {
        private String verificationId;
        private boolean compliant;
        private Instant verificationTimestamp;
        private String publicKeyFingerprint;
        private String publicKeyAlgorithm;
        private String hsmVendor;
        private String hsmModel;
        private String hsmSerialNumber;
        private String supplierIdentifier;
        private String supplierName;
        private String keyPurpose;
        private String countryCode;
        private boolean generatedOnDevice;
        private boolean exportable;
        private boolean attestationChainValid;
        private boolean publicKeyMatchesAttestation;
        private boolean article5_2b;
        private boolean article6_10;
        private boolean article9_3c;
        private boolean article9_3d;
        private boolean article9_4d;
        private boolean article28_1a;
        private String doraSummary;
        private String signatureBase64;
        private String signingCertificatePem;
        private List<String> errors;
        private List<String> warnings;

        public static VerifyResponseSummary from(VerifyResponse r) {
            if (r == null) {
                return null;
            }
            VerifyResponse.KeyProperties kp = r.getKeyProperties();
            VerifyResponse.DoraCompliance dc = r.getDoraCompliance();
            return VerifyResponseSummary.builder()
                    .verificationId(r.getVerificationId())
                    .compliant(r.isCompliant())
                    .verificationTimestamp(r.getVerificationTimestamp())
                    .publicKeyFingerprint(r.getPublicKeyFingerprint())
                    .publicKeyAlgorithm(r.getPublicKeyAlgorithm())
                    .hsmVendor(r.getHsmVendor())
                    .hsmModel(r.getHsmModel())
                    .hsmSerialNumber(r.getHsmSerialNumber())
                    .supplierIdentifier(r.getSupplierIdentifier())
                    .supplierName(r.getSupplierName())
                    .keyPurpose(r.getKeyPurpose())
                    .countryCode(r.getCountryCode())
                    .generatedOnDevice(kp != null && kp.isGeneratedOnDevice())
                    .exportable(kp != null && kp.isExportable())
                    .attestationChainValid(kp != null && kp.isAttestationChainValid())
                    .publicKeyMatchesAttestation(kp != null && kp.isPublicKeyMatchesAttestation())
                    .article5_2b(dc != null && dc.isArticle5_2b())
                    .article6_10(dc != null && dc.isArticle6_10())
                    .article9_3c(dc != null && dc.isArticle9_3c())
                    .article9_3d(dc != null && dc.isArticle9_3d())
                    .article9_4d(dc != null && dc.isArticle9_4d())
                    .article28_1a(dc != null && dc.isArticle28_1a())
                    .doraSummary(dc == null ? null : dc.getSummary())
                    .signatureBase64(r.getSignature())
                    .signingCertificatePem(r.getSigningCertificate())
                    .errors(r.getErrors())
                    .warnings(r.getWarnings())
                    .build();
        }
    }

    /**
     * Audit-friendly view of the gatekeeper confirm-step response.
     */
    @Data
    @Builder
    public static class IssuanceConfirmResponseSummary {
        private String verificationId;
        private boolean loopClosed;
        private Boolean publicKeyMatch;
        private String expectedPublicKeyFingerprint;
        private String actualPublicKeyFingerprint;
        private IssuanceConfirmResponse.RegistryStatus registryStatus;
        private String processedTimestamp;
        private List<String> anomalies;

        public static IssuanceConfirmResponseSummary from(IssuanceConfirmResponse r) {
            if (r == null) {
                return null;
            }
            return IssuanceConfirmResponseSummary.builder()
                    .verificationId(r.getVerificationId())
                    .loopClosed(r.isLoopClosed())
                    .publicKeyMatch(r.getPublicKeyMatch())
                    .expectedPublicKeyFingerprint(r.getExpectedPublicKeyFingerprint())
                    .actualPublicKeyFingerprint(r.getActualPublicKeyFingerprint())
                    .registryStatus(r.getRegistryStatus())
                    .processedTimestamp(r.getProcessedTimestamp())
                    .anomalies(r.getAnomalies())
                    .build();
        }
    }

    @Data
    @Builder
    public static class IssuedCertificateSummary {
        private String certificatePem;
        private String issuerDn;
        private String subjectDn;
        private Instant notBefore;
        private Instant notAfter;
        private String issuanceId;
        private String verifyReceiptId;

        public static IssuedCertificateSummary from(IssuedCertificate c) {
            if (c == null) {
                return null;
            }
            return IssuedCertificateSummary.builder()
                    .certificatePem(c.certificatePem())
                    .issuerDn(c.issuerDn())
                    .subjectDn(c.subjectDn())
                    .notBefore(c.notBefore())
                    .notAfter(c.notAfter())
                    .issuanceId(c.issuanceId())
                    .verifyReceiptId(c.verifyReceiptId())
                    .build();
        }
    }
}
