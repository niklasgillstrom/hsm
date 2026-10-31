package eu.gillstrom.hsm.verification;

import java.security.cert.X509Certificate;

/**
 * Test-only access to the package-private constructors that anchor a verifier
 * at a root other than the pinned one, for tests outside this package.
 */
public final class TestVerifiers {

    private TestVerifiers() {
    }

    /** A {@link YubicoVerifier} whose PKIX trust anchor is {@code root} instead of the pinned Yubico root. */
    public static YubicoVerifier yubicoAnchoredAt(X509Certificate root) {
        return new YubicoVerifier(root);
    }

    /** A {@link SecurosysVerifier} whose PKIX trust anchor is {@code root} instead of the pinned Securosys root. */
    public static SecurosysVerifier securosysAnchoredAt(X509Certificate root) {
        return new SecurosysVerifier(root);
    }
}
