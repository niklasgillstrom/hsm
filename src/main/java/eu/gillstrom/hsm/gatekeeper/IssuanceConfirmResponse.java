package eu.gillstrom.hsm.gatekeeper;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Response to {@code POST /v1/attestation/{countryCode}/confirm}. Records
 * whether the issued certificate matched the attested public key and
 * what final state the gatekeeper's approval registry now holds.
 */
@Data
@Builder
public class IssuanceConfirmResponse {

    /** Echoes the verify-step verification ID. */
    private String verificationId;

    /** True iff the gatekeeper considers the supervisory loop closed. */
    private boolean loopClosed;

    /**
     * True iff the public key in the issued certificate matches the public
     * key approved in the verify step. Null on a non-issuance confirmation.
     */
    private Boolean publicKeyMatch;

    /** Fingerprint recorded by the gatekeeper at verify time. */
    private String expectedPublicKeyFingerprint;

    /** Fingerprint extracted from the submitted certificate; null on non-issuance. */
    private String actualPublicKeyFingerprint;

    /** Final approval-registry status after this confirmation. */
    private RegistryStatus registryStatus;

    /** ISO-8601 instant when the gatekeeper processed this confirmation. */
    private String processedTimestamp;

    /** Anomaly strings detected during confirmation; empty list when none. */
    private List<String> anomalies;

    /**
     * Approval-registry states. Anything starting with {@code ANOMALY_} is a
     * supervisory concern that should be followed up by the operating NCA.
     */
    public enum RegistryStatus {
        /** Attestation approved, certificate issued, public key matches. */
        VERIFIED_AND_ISSUED,
        /** Attestation approved, certificate not issued (entity withdrew etc). */
        VERIFIED_NOT_ISSUED,
        /** Attestation rejected, certificate correctly not issued. */
        REJECTED_NOT_ISSUED,
        /** Certificate issued despite gatekeeper rejection. */
        ANOMALY_ISSUED_DESPITE_REJECTION,
        /** Public key in issued certificate does not match the attested key. */
        ANOMALY_PUBLIC_KEY_MISMATCH,
        /** Confirmation received for a verificationId not in the registry. */
        ANOMALY_UNKNOWN_VERIFICATION
    }
}
