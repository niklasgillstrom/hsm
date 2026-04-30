package eu.gillstrom.hsm.gatekeeper;

/**
 * Client for the gatekeeper's two-step supervisory protocol — the abstraction
 * that lets the financial entity hand decision-relevant attestation evidence
 * to a structurally separate authority and receive cryptographically signed
 * supervisory artefacts.
 *
 * <p>The protocol has two legs:
 * <ol>
 *   <li>{@link #verify(VerifyRequest)} — submit the attested public key
 *       and HSM-attestation evidence; gatekeeper independently re-runs the
 *       verification and returns a signed {@link VerifyResponse}.</li>
 *   <li>{@link #confirm(IssuanceConfirmRequest)} — after the financial
 *       entity issues the certificate (or refuses to), submit the issued
 *       certificate (or non-issuance reason) so the gatekeeper can confirm
 *       that the public key in the certificate matches the one it
 *       approved, and update its approval registry accordingly.</li>
 * </ol>
 *
 * <p>The architecture is the supervisory complement to DORA Regulation (EU)
 * 2022/2554 Article 6(10): the financial entity remains fully responsible
 * for the verification of compliance with DORA; the gatekeeper does not
 * relieve it of that duty. What the gatekeeper provides is independent
 * supervisory evidence that the cryptographic control was actually
 * executed — evidence that, by virtue of being signed by a structurally
 * separate party, is not self-attested. The operating gatekeeper acts under
 * EBA mandate Regulation (EU) No 1093/2010 Articles 17(6) (breach of Union
 * law investigations) and 29 (common supervisory culture).
 *
 * <p>Implementations:
 * <ul>
 *   <li>{@link FailClosedGatekeeperClient} — refuses every call, the
 *       reference default. SIGNING-certificate issuance fails until a real
 *       gatekeeper is wired in. Selected when {@code swish.gatekeeper.mode}
 *       is unset or {@code fail-closed}.</li>
 *   <li>{@link MockGatekeeperClient} — signs receipts with an ephemeral
 *       in-process key, for tests and demos. Selected via
 *       {@code swish.gatekeeper.mode=mock}.</li>
 *   <li>{@link HttpGatekeeperClient} — POSTs JSON to the configured
 *       gatekeeper URL. Selected via {@code swish.gatekeeper.mode=http}.</li>
 * </ul>
 */
public interface GatekeeperClient {

    /**
     * Submit attestation evidence for independent verification.
     *
     * @param request canonical evidence (public key, vendor, attestation chain, ...)
     * @return signed receipt, including the gatekeeper's compliance determination
     * @throws GatekeeperException if the call cannot be completed (transport,
     *         configuration). A response with {@code compliant=false} is NOT
     *         thrown — that is returned normally.
     */
    VerifyResponse verify(VerifyRequest request) throws GatekeeperException;

    /**
     * Notify the gatekeeper of the issuance / non-issuance decision so it
     * can close the supervisory loop in its approval registry.
     *
     * @throws GatekeeperException if the call cannot be completed; the
     *         caller's certificate is by then already issued, so this should
     *         be treated as an anomalous-but-recoverable state, not a
     *         rejection. See
     *         {@code IssuanceResponse.issuedButConfirmFailed} for the
     *         outcome representation.
     */
    IssuanceConfirmResponse confirm(IssuanceConfirmRequest request) throws GatekeeperException;
}
