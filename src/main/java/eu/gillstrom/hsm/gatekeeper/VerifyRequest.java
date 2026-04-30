package eu.gillstrom.hsm.gatekeeper;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Wire payload for {@code POST /v1/attestation/{countryCode}/verify} —
 * the first leg of the supervisory two-step protocol described in
 * Gillström (in preparation, Capital Markets Law Journal and Computer Law
 * &amp; Security Review).
 *
 * <p>The financial entity submits the attested public key plus the
 * vendor-specific cryptographic evidence; the gatekeeper independently
 * re-runs the HSM-attestation check and returns a signed receipt
 * ({@link VerifyResponse}). The signed receipt is the supervisory
 * evidence the financial entity later presents to its National Competent
 * Authority under DORA Regulation (EU) 2022/2554 Article 6(10), which
 * makes the entity fully responsible for the verification of compliance
 * but does not preclude that verification being witnessed by a structurally
 * independent party — see also DORA Articles 9(3)(d) and 9(4)(d).
 *
 * <p>The gatekeeper itself acts under the EBA mandate of Regulation (EU)
 * No 1093/2010 Articles 17(6) and 29 (or equivalent national mandate of
 * the operating NCA, in Sweden Finansinspektionen).
 *
 * <p>Note: the wire format submits the <em>public key</em>, not a CSR.
 * Subject DN, BankID material, organisation numbers and other surrounding
 * KYC metadata are intentionally excluded — the gatekeeper certifies the
 * cryptographic HSM-attestation property only, not the financial entity's
 * own KYC checks.
 */
@Data
@Builder
public class VerifyRequest {

    /** PEM-encoded attested public key. NOT a CSR. */
    private String publicKey;

    /** {@code YUBICO}, {@code SECUROSYS}, {@code AZURE}, or {@code GOOGLE}. */
    private String hsmVendor;

    /** Vendor-specific attestation blob (base64). Null for Yubico. */
    private String attestationData;

    /** Detached attestation signature (base64). Null except for Securosys. */
    private String attestationSignature;

    /** PEM-encoded chain (excluding manufacturer root, which the gatekeeper pins). */
    private List<String> attestationCertChain;

    /** Optional: orgnr of the technical supplier whose key is being attested. */
    private String supplierIdentifier;

    /** Optional: human-readable supplier name. */
    private String supplierName;

    /** Optional: free-text purpose tag, e.g. {@code "Swish payment signing"}. */
    private String keyPurpose;

    /**
     * ISO 3166-1 alpha-2 jurisdiction. The gatekeeper sets this from the
     * URL path on receipt; the field on the request is informational and
     * MUST match the path value.
     */
    private String countryCode;
}
