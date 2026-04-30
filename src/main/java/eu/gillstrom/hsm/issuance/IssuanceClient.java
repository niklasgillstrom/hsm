package eu.gillstrom.hsm.issuance;

import eu.gillstrom.hsm.model.CertificateRequest;

/**
 * Issues a Swish certificate after local verification and gatekeeper verify
 * have both succeeded. The reference implementation ships only
 * {@link MockIssuanceClient}; production deployments wire up an external
 * Getswish CA integration through this interface.
 *
 * <p>The {@code verifyReceiptId} parameter is the gatekeeper's
 * {@code verificationId} from the verify-step receipt; the issuer embeds it
 * (or its hash) in audit records so the issuance is bound to a specific
 * supervisory authorisation. After issuance the orchestrator (the
 * {@code AttestationService}) is responsible for calling the gatekeeper's
 * confirm endpoint with the issued certificate.
 */
public interface IssuanceClient {

    /**
     * @param request the original CertificateRequest (includes CSR, subject DN, etc.)
     * @param verifyReceiptId the gatekeeper {@code verificationId} from the
     *                        verify step, or null for non-witnessed flows
     *                        (e.g. TRANSPORT certificates)
     * @return the issued certificate, including audit metadata
     * @throws IssuanceException if the CA refuses to issue or the call fails
     */
    IssuedCertificate issue(CertificateRequest request, String verifyReceiptId) throws IssuanceException;
}
