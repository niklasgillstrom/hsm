package eu.gillstrom.hsm.util;

import java.security.MessageDigest;
import java.security.PublicKey;

/**
 * The single canonical public-key fingerprint format used on the wire between
 * this repository and the gatekeeper.
 *
 * <p>SHA-256 over the SubjectPublicKeyInfo encoding, rendered as LOWERCASE hex
 * with colon separators ({@code "ab:cd:..."}). Byte-for-byte the same format as
 * the gatekeeper repository's {@code eu.gillstrom.gatekeeper.util.Fingerprints}
 * — {@code VerifyResponse.publicKeyFingerprint} is produced there and compared
 * here, so a divergence in case or separator silently breaks the comparison
 * rather than failing loudly.</p>
 *
 * <p>Not to be confused with
 * {@link eu.gillstrom.hsm.gatekeeper.GatekeeperKeyRegistry#fingerprintHex(PublicKey)},
 * which uses colon-free lowercase hex. That format is a purely local map key for
 * the trusted-certificate registry and never travels on the wire; the two must
 * not be substituted for one another.</p>
 *
 * <p>Do not reimplement this format. Call it from production code and from
 * tests alike, so that a test cannot encode a format the production writer does
 * not produce.</p>
 */
public final class Fingerprints {

    private Fingerprints() {
    }

    /** Canonical fingerprint of a public key. */
    public static String ofPublicKey(PublicKey key) {
        return ofSubjectPublicKeyInfo(key.getEncoded());
    }

    /** Canonical fingerprint of an already-encoded SubjectPublicKeyInfo. */
    public static String ofSubjectPublicKeyInfo(byte[] subjectPublicKeyInfo) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(subjectPublicKeyInfo);
            StringBuilder sb = new StringBuilder(hash.length * 3);
            for (int i = 0; i < hash.length; i++) {
                if (i > 0) {
                    sb.append(':');
                }
                sb.append(String.format("%02x", hash[i] & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            // SHA-256 is mandatory in every JRE (JCA guarantee).
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Constant-time, case-insensitive equality of two canonical fingerprints.
     * Returns {@code false} if either side is null — a missing fingerprint is
     * never a match.
     */
    public static boolean equal(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
                a.trim().toLowerCase(java.util.Locale.ROOT).getBytes(java.nio.charset.StandardCharsets.UTF_8),
                b.trim().toLowerCase(java.util.Locale.ROOT).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
