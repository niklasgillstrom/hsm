package eu.gillstrom.hsm.gatekeeper;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;

/**
 * Signed verification receipt returned by the gatekeeper from
 * {@code POST /v1/attestation/{countryCode}/verify}.
 *
 * <p>This is a cryptographic, traceable record — not a simple boolean
 * response. The financial entity retains it as supervisory evidence
 * that an independent authority (the operating National Competent
 * Authority, in Sweden Finansinspektionen, acting under EBA mandate
 * Regulation (EU) No 1093/2010 Articles 17(6) and 29) re-ran the
 * HSM-attestation check and agreed with the entity's local conclusion.
 *
 * <p>The signature in {@link #signature} covers the canonical byte
 * representation produced by {@link ReceiptCanonicalizer#canonicalize(VerifyResponse)},
 * not the JSON wire form. The signing key is documented in
 * {@link #signingCertificate} and must be present in the financial
 * entity's local {@link GatekeeperKeyRegistry} for the receipt to be
 * trusted.
 *
 * <p>Field shape mirrors the gatekeeper's
 * {@code eu.gillstrom.gatekeeper.model.VerificationResponse} byte-for-byte
 * so that the same {@link ReceiptCanonicalizer} logic produces identical
 * output on both sides of the wire — a deviation breaks signature
 * verification.
 */
@Data
@Builder
public class VerifyResponse {

    /** Primary key linking verify, registry, this receipt, and the confirm step. */
    private String verificationId;

    /**
     * Server-issued single-use nonce. The financial entity must echo this
     * value back when calling the gatekeeper's confirm endpoint at Step 7;
     * the gatekeeper rejects any confirm whose submitted nonce does not
     * match the one bound to the verificationId at verify time. This binds
     * the confirm call to the original verify call and prevents replay by
     * an attacker who has obtained a valid issuer-CA-chained certificate
     * and learned a verificationId out of band.
     */
    private String confirmationNonce;

    /** Binary HSM-protection determination by the gatekeeper. */
    private boolean compliant;

    /** ISO-8601 instant of when the gatekeeper completed verification. */
    private Instant verificationTimestamp;

    /** Base64 detached signature over {@link ReceiptCanonicalizer#canonicalize}. */
    private String signature;

    /** PEM-encoded gatekeeper signing certificate (full chain when present). */
    private String signingCertificate;

    private String publicKeyFingerprint;
    private String publicKeyAlgorithm;

    private String hsmVendor;
    private String hsmModel;
    private String hsmSerialNumber;

    private KeyProperties keyProperties;
    private DoraCompliance doraCompliance;

    private String supplierIdentifier;
    private String supplierName;
    private String keyPurpose;
    private String countryCode;

    private List<String> errors;
    private List<String> warnings;

    /** Decision-relevant key flags. All four must be true for compliance. */
    @Data
    @Builder
    public static class KeyProperties {
        /** True iff the key was generated inside the device, never imported. */
        private boolean generatedOnDevice;
        /** False iff the key is non-extractable. {@code true} is a CRITICAL failure. */
        private boolean exportable;
        /** True iff the attestation chain validates against the manufacturer root. */
        private boolean attestationChainValid;
        /** True iff the public key in the attestation matches the submitted public key. */
        private boolean publicKeyMatchesAttestation;
    }

    /**
     * DORA article-by-article mapping. Each boolean records whether the
     * gatekeeper considers the corresponding obligation satisfied by the
     * cryptographic evidence presented; the {@link #summary} is for human
     * supervisory review.
     */
    @Data
    @Builder
    public static class DoraCompliance {
        /** Article 5(2)(b) — management body maintains high standards. */
        private boolean article5_2b;
        /** Article 6(10) — entity remains fully responsible for verification. */
        private boolean article6_10;
        /** Article 9(3)(c) — prevent impairment of authenticity and integrity. */
        private boolean article9_3c;
        /** Article 9(3)(d) — protection against poor administration. */
        private boolean article9_3d;
        /** Article 9(4)(d) — strong authentication via dedicated control systems. */
        private boolean article9_4d;
        /** Article 28(1)(a) — entity remains fully responsible. */
        private boolean article28_1a;
        /** Free-text supervisory summary. */
        private String summary;
    }
}
