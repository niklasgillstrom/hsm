package eu.gillstrom.hsm.gatekeeper;

import java.nio.charset.StandardCharsets;
import java.util.StringJoiner;

/**
 * Produces the canonical byte representation of a verification receipt that
 * is covered by the gatekeeper's signature in
 * {@link VerifyResponse#getSignature()}.
 *
 * <p>This is a byte-identical mirror of the gatekeeper's
 * {@code eu.gillstrom.gatekeeper.signing.ReceiptCanonicalizer}. Any
 * deviation breaks signature verification — both sides MUST produce
 * identical bytes for the same logical input.
 *
 * <p>The canonical form is a UTF-8 string built from a fixed, documented
 * ordering of decision-relevant fields, each escaped by URL-encoding the
 * pipe character so ambiguity between field separators and field contents
 * is impossible. Null fields are rendered as the empty string; boolean fields
 * render as {@code true} / {@code false}; instants as ISO-8601 with offset
 * {@code Z}. A version marker ({@code v3}, see {@link #CANONICAL_VERSION})
 * is prefixed so that future canonical changes can be introduced
 * non-ambiguously.
 *
 * <p>If a future receipt field becomes decision-relevant it MUST be added
 * here, and the version marker MUST be bumped on both sides simultaneously.
 * A receipt signed under another version does not verify.
 */
public final class ReceiptCanonicalizer {

    private ReceiptCanonicalizer() {
    }

    public static final String CANONICAL_VERSION = "v3";

    /**
     * The form before 1.6.0, without the customer's organisation and Swish
     * numbers and the supplier number. Receipts signed then are retained for
     * five years and stay verifiable with it.
     */
    public static final String PREVIOUS_VERSION = "v2";

    public static byte[] canonicalize(VerifyResponse r) {
        return canonicalize(r, CANONICAL_VERSION);
    }

    /** Whether the receipt carries a field that only {@link #CANONICAL_VERSION} signs. */
    public static boolean hasCurrentOnlyFields(VerifyResponse r) {
        return r.getCustomerOrganisationNumber() != null || r.getCustomerSwishNumber() != null
                || r.getSupplierNumber() != null;
    }

    /**
     * @param version {@link #CANONICAL_VERSION} or {@link #PREVIOUS_VERSION}
     */
    public static byte[] canonicalize(VerifyResponse r, String version) {
        if (r == null) {
            throw new IllegalArgumentException("Receipt must not be null");
        }
        boolean current = CANONICAL_VERSION.equals(version);
        if (!current && !PREVIOUS_VERSION.equals(version)) {
            throw new IllegalArgumentException("Unknown canonical version " + version);
        }
        StringJoiner j = new StringJoiner("|");
        j.add(version);
        j.add(safe(r.getVerificationId()));
        j.add(safe(r.getConfirmationNonce()));
        j.add(Boolean.toString(r.isCompliant()));
        j.add(r.getVerificationTimestamp() == null ? "" : r.getVerificationTimestamp().toString());
        j.add(safe(r.getPublicKeyFingerprint()));
        j.add(safe(r.getPublicKeyAlgorithm()));
        j.add(safe(r.getHsmVendor()));
        j.add(safe(r.getHsmModel()));
        j.add(safe(r.getHsmSerialNumber()));
        if (current) {
            j.add(safe(r.getCustomerOrganisationNumber()));
            j.add(safe(r.getCustomerSwishNumber()));
        }
        j.add(safe(r.getSupplierIdentifier()));
        if (current) {
            j.add(safe(r.getSupplierNumber()));
        }
        j.add(safe(r.getSupplierName()));
        j.add(safe(r.getKeyPurpose()));
        j.add(safe(r.getCountryCode()));

        // Key properties — decision-relevant
        if (r.getKeyProperties() != null) {
            j.add(Boolean.toString(r.getKeyProperties().isGeneratedOnDevice()));
            j.add(Boolean.toString(r.getKeyProperties().isExportable()));
            j.add(Boolean.toString(r.getKeyProperties().isAttestationChainValid()));
            j.add(Boolean.toString(r.getKeyProperties().isPublicKeyMatchesAttestation()));
        } else {
            j.add("").add("").add("").add("");
        }

        // DORA article bits — decision-relevant
        if (r.getDoraCompliance() != null) {
            var d = r.getDoraCompliance();
            j.add(Boolean.toString(d.isArticle5_2b()));
            j.add(Boolean.toString(d.isArticle6_10()));
            j.add(Boolean.toString(d.isArticle9_3c()));
            j.add(Boolean.toString(d.isArticle9_3d()));
            j.add(Boolean.toString(d.isArticle9_4d()));
            j.add(Boolean.toString(d.isArticle28_1a()));
        } else {
            j.add("").add("").add("").add("").add("").add("");
        }

        return j.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Escape pipe characters in field values by percent-encoding, so a field
     * that happens to contain {@code |} cannot desynchronise the canonical form.
     * The {@code %} character must be escaped first to keep the encoding
     * reversible.
     */
    private static String safe(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("%", "%25").replace("|", "%7C");
    }
}
