package eu.gillstrom.hsm.issuance;

public class IssuanceException extends RuntimeException {
    public IssuanceException(String message) {
        super(message);
    }
    public IssuanceException(String message, Throwable cause) {
        super(message, cause);
    }
}
