package eu.gillstrom.hsm.gatekeeper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Default {@link GatekeeperClient} implementation. Refuses every gatekeeper
 * call and emits a {@code WARN}-level log on every invocation, so a
 * deployment that forgets to configure a real gatekeeper fails closed in a
 * way that is loudly visible in operational logs.
 *
 * <p>Selected when {@code swish.gatekeeper.mode} is unset or set to
 * {@code fail-closed}. SIGNING-certificate requests will be rejected with
 * the error returned in {@code IssuanceResponse.errors} since
 * {@link #verify} always throws and no {@link VerifyResponse} is ever
 * produced.
 *
 * <p>This is the correct posture under DORA Article 6(10): if no
 * structurally independent supervisory authority can witness the
 * verification, the financial entity cannot present non-self-attested
 * evidence — and so should not issue a SIGNING certificate that depends
 * on that evidence.
 */
@Component
@ConditionalOnProperty(name = "swish.gatekeeper.mode", havingValue = "fail-closed", matchIfMissing = true)
public class FailClosedGatekeeperClient implements GatekeeperClient {

    private static final Logger log = LoggerFactory.getLogger(FailClosedGatekeeperClient.class);

    public FailClosedGatekeeperClient() {
        log.warn("FailClosedGatekeeperClient is active: every gatekeeper call will be rejected. "
                + "This is the REFERENCE default. SIGNING-certificate requests will fail until "
                + "a real GatekeeperClient is wired up "
                + "(swish.gatekeeper.mode=http or swish.gatekeeper.mode=mock).");
    }

    @Override
    public VerifyResponse verify(VerifyRequest request) {
        log.warn("FailClosedGatekeeperClient.verify called — rejecting "
                + "(no gatekeeper configured)");
        throw new GatekeeperException(
                "No GatekeeperClient is configured. Set swish.gatekeeper.mode and "
                        + "swish.gatekeeper.url, and configure trusted gatekeeper certificates "
                        + "via swish.gatekeeper.trusted-keys.");
    }

    @Override
    public IssuanceConfirmResponse confirm(IssuanceConfirmRequest request) {
        log.warn("FailClosedGatekeeperClient.confirm called — rejecting "
                + "(no gatekeeper configured)");
        throw new GatekeeperException(
                "No GatekeeperClient is configured. Confirmation cannot be sent.");
    }
}
