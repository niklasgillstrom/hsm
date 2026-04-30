package eu.gillstrom.hsm.service;

/**
 * Verifies that a holder of a Swedish BankID (identified by
 * {@code personalNumber}) is authorised to act as a signatory for the given
 * {@code organisationNumber} — typically because they are a registered
 * firmatecknare at Bolagsverket, listed in the Swish membership agreement,
 * or otherwise granted signing authority for the organisation.
 *
 * <p>This is a pluggable abstraction. The reference implementation ships
 * with two implementations:</p>
 *
 * <ul>
 *   <li>{@link FailClosedSignatoryRightsVerifier} — the default. Returns
 *       {@link Result#unauthorised(String)} for every query and emits a
 *       {@code WARN} log. Intended for deployments that have not yet wired
 *       up a real registry, so the gap is loud rather than silent.</li>
 *   <li>{@link MockAgreementRegistrySignatoryRightsVerifier} — loads
 *       (personalNumber, organisationNumber) pairs from a configuration
 *       file and treats the union as authoritative. Demonstrates the
 *       integration shape without requiring Swish, Bolagsverket or
 *       other external credentials. Active when
 *       {@code swish.signatory-rights.mode=mock-registry}.</li>
 * </ul>
 *
 * <p>A production deployment must supply a Bolagsverket-backed or
 * Swish-agreement-registry-backed implementation. The interface accepts
 * the same three inputs the production query would take so that the
 * swap is a no-op at the call site.</p>
 */
public interface SignatoryRightsVerifier {

    /**
     * Check whether the holder of the BankID {@code personalNumber} is
     * authorised to act as a signatory for {@code organisationNumber}.
     * Implementations must never throw for missing or malformed inputs —
     * instead return {@link Result#unauthorised(String)} with a diagnostic
     * reason string.
     *
     * @param personalNumber     Swedish personnummer (12 digits, no separator)
     *                           — never null in practice because it is
     *                           extracted from a BankID certificate, but
     *                           implementations must defend against null.
     * @param organisationNumber Swedish organisationsnummer (10 digits)
     * @param swishNumber        Swish agreement number — optional context,
     *                           may be null. Production implementations that
     *                           query the Swish agreement registry will use
     *                           this to scope the authorisation check.
     */
    Result check(String personalNumber, String organisationNumber, String swishNumber);

    /**
     * Structured outcome. Callers must treat any non-authorised outcome as
     * a hard fail — including the {@code UNKNOWN} case where the registry
     * could not answer (fail-closed semantics).
     */
    record Result(Status status, String reason, String source) {

        public enum Status {
            /** The registry confirms the signatory is authorised. */
            AUTHORISED,
            /** The registry confirms the signatory is not authorised. */
            UNAUTHORISED,
            /**
             * The registry could not answer (transport failure, missing
             * credentials, placeholder implementation). Callers must treat
             * this as unauthorised.
             */
            UNKNOWN
        }

        public boolean isAuthorised() {
            return status == Status.AUTHORISED;
        }

        public static Result authorised(String source) {
            return new Result(Status.AUTHORISED, null, source);
        }

        public static Result unauthorised(String reason) {
            return new Result(Status.UNAUTHORISED, reason, null);
        }

        public static Result unknown(String reason) {
            return new Result(Status.UNKNOWN, reason, null);
        }
    }
}
