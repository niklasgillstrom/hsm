package eu.gillstrom.hsm.gatekeeper;

/**
 * Thrown by {@link GatekeeperClient} implementations when the gatekeeper
 * call itself cannot be completed — network timeout, gatekeeper unreachable,
 * configuration missing, malformed response. A successful call that returns
 * {@code compliant=false} is NOT thrown — that is a legitimate supervisory
 * outcome and is delivered through {@link VerifyResponse}.
 */
public class GatekeeperException extends RuntimeException {

    public GatekeeperException(String message) {
        super(message);
    }

    public GatekeeperException(String message, Throwable cause) {
        super(message, cause);
    }
}
