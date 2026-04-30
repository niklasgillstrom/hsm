package eu.gillstrom.hsm.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Default {@link SignatoryRightsVerifier}. Returns
 * {@link Result.Status#UNKNOWN} for every query and emits a prominent
 * {@code WARN} log so that the absence of a real registry integration is
 * impossible to miss in production.
 *
 * <p>Active when {@code swish.signatory-rights.mode} is unset or set to
 * {@code fail-closed}. Replace with a Bolagsverket- or
 * Swish-agreement-registry-backed implementation before production
 * deployment.</p>
 */
@Component
@ConditionalOnProperty(name = "swish.signatory-rights.mode", havingValue = "fail-closed", matchIfMissing = true)
public class FailClosedSignatoryRightsVerifier implements SignatoryRightsVerifier {

    private static final Logger log = LoggerFactory.getLogger(FailClosedSignatoryRightsVerifier.class);

    public FailClosedSignatoryRightsVerifier() {
        log.warn("FailClosedSignatoryRightsVerifier is active: every signatory-rights query will return UNKNOWN. "
                + "This is the REFERENCE default and ALL signing-certificate requests will fail signatory "
                + "authorisation. Wire up a real implementation (swish.signatory-rights.mode=mock-registry "
                + "for demonstration, or supply a Bolagsverket/Swish-agreement-registry adapter) before "
                + "production deployment.");
    }

    @Override
    public Result check(String personalNumber, String organisationNumber, String swishNumber) {
        log.warn("SignatoryRightsVerifier queried for organisationNumber={} — no registry configured, "
                + "returning UNKNOWN (caller will fail-closed).", organisationNumber);
        return Result.unknown("No signatory-rights registry configured — fail-closed by default.");
    }
}
