package eu.gillstrom.hsm.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fail-closed default must return {@link SignatoryRightsVerifier.Result.Status#UNKNOWN}
 * for every query so downstream callers treat the absence of a registry as a
 * hard failure.
 */
class FailClosedSignatoryRightsVerifierTest {

    @Test
    void alwaysReturnsUnknown() {
        FailClosedSignatoryRightsVerifier verifier = new FailClosedSignatoryRightsVerifier();

        SignatoryRightsVerifier.Result result = verifier.check("198001011234", "5566778899", null);

        assertThat(result.status()).isEqualTo(SignatoryRightsVerifier.Result.Status.UNKNOWN);
        assertThat(result.isAuthorised()).isFalse();
        assertThat(result.reason()).isNotBlank();
    }

    @Test
    void unknownForNullInputsToo() {
        FailClosedSignatoryRightsVerifier verifier = new FailClosedSignatoryRightsVerifier();

        SignatoryRightsVerifier.Result result = verifier.check(null, null, null);

        assertThat(result.status()).isEqualTo(SignatoryRightsVerifier.Result.Status.UNKNOWN);
    }
}
