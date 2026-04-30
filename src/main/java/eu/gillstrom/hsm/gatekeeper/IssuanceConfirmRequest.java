package eu.gillstrom.hsm.gatekeeper;

import lombok.Builder;
import lombok.Data;

/**
 * Wire payload for {@code POST /v1/attestation/{countryCode}/confirm} —
 * the second leg of the supervisory two-step protocol. Closes the loop
 * by handing the gatekeeper the actual issued certificate (or a
 * non-issuance notice), so the gatekeeper can independently confirm
 * that the public key in the issued certificate matches the one it
 * approved in the verify step.
 *
 * <p>This is a cryptographic correspondence check, not a contractual
 * one. The gatekeeper extracts the public key from
 * {@link #signingCertificatePem} and compares its fingerprint with the
 * fingerprint recorded in the registry under {@link #verificationId};
 * a mismatch lands the verification in {@code ANOMALY_PUBLIC_KEY_MISMATCH}.
 */
@Data
@Builder
public class IssuanceConfirmRequest {

    /** UUID returned by the gatekeeper in the verify step. */
    private String verificationId;

    /**
     * Single-use nonce echoed back from
     * {@link VerifyResponse#getConfirmationNonce()}. The gatekeeper
     * rejects the confirm with HTTP 400 if this does not match the nonce
     * bound at verify time. Step-7 replay binding — without this, an
     * attacker who has obtained a valid issuer-CA-chained certificate
     * and learned a verificationId out of band could flood the gatekeeper
     * with confirm calls.
     */
    private String confirmationNonce;

    /** True iff a certificate was actually issued. */
    private boolean issued;

    /** PEM of the issued signing certificate. Null when {@code issued=false}. */
    private String signingCertificatePem;

    /** ISO-8601 instant of the issuance / non-issuance decision. */
    private String timestamp;

    /** Reason text when {@code issued=false}; null otherwise. */
    private String nonIssuanceReason;

    /** Swish number whose certificate this is. */
    private String swishNumber;

    /** Organisation number of the corporate customer. */
    private String organisationNumber;
}
