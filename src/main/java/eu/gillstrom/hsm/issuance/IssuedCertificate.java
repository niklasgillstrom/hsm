package eu.gillstrom.hsm.issuance;

import java.time.Instant;

/**
 * A certificate issued by an {@link IssuanceClient}. The reference shape carries
 * the PEM-encoded leaf, the issuer subject, the validity window, and an
 * issuer-side identifier; production implementations may add audit metadata.
 *
 * <p>{@code verifyReceiptId} is the gatekeeper's {@code verificationId} from
 * the verify-step receipt (or null for non-witnessed issuance, e.g. TRANSPORT
 * certificates). The issuer records it so that issuance is auditably bound
 * to a specific supervisory authorisation — and so the orchestrator can
 * later call the gatekeeper's confirm endpoint quoting the same id.
 */
public record IssuedCertificate(
        String certificatePem,
        String issuerDn,
        String subjectDn,
        Instant notBefore,
        Instant notAfter,
        String issuanceId,
        String verifyReceiptId
) {
}
