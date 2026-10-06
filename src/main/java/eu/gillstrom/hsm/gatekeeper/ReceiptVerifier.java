package eu.gillstrom.hsm.gatekeeper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

/**
 * Verifies that an {@link VerifyResponse} is genuinely signed by a
 * gatekeeper whose certificate is in the local {@link GatekeeperKeyRegistry}.
 * This closes the supervisory trust loop: the financial entity does not
 * blindly accept any signed receipt — it confirms that
 * <ol>
 *   <li>the {@code signingCertificate} on the receipt parses as a real
 *       X.509 certificate,</li>
 *   <li>that certificate's public key is registered as a trusted gatekeeper
 *       in {@link GatekeeperKeyRegistry}, and</li>
 *   <li>the {@code signature} verifies under that public key over the
 *       canonical bytes produced by
 *       {@link ReceiptCanonicalizer#canonicalize(VerifyResponse)}.</li>
 * </ol>
 *
 * <p>Rejection paths are logged at {@code WARN} so an operator can see when
 * a receipt is being silently dropped — silent rejection is itself a
 * supervisory failure.
 */
@Component
public class ReceiptVerifier {

    private static final Logger log = LoggerFactory.getLogger(ReceiptVerifier.class);

    /** Default signature algorithm — RSA-SHA256, matches gatekeeper signers. */
    private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";

    private final GatekeeperKeyRegistry registry;

    public ReceiptVerifier(GatekeeperKeyRegistry registry) {
        if (registry == null) {
            throw new IllegalArgumentException("registry must not be null");
        }
        this.registry = registry;
    }

    /**
     * @return {@code true} if the receipt is authentic and signed by a
     *         trusted gatekeeper; {@code false} if any check fails. Reasons
     *         are logged at WARN level.
     */
    public boolean verify(VerifyResponse receipt) {
        if (receipt == null) {
            log.warn("ReceiptVerifier: null receipt");
            return false;
        }
        return verifySigned("receipt", receipt.getVerificationId(), receipt.getSignature(),
                receipt.getSigningCertificate(), () -> ReceiptCanonicalizer.canonicalize(receipt));
    }

    /**
     * Verify a Step-7 confirmation response the same way as a receipt: the
     * advertised certificate's key must be registered, and the signature must
     * verify over {@link ConfirmationCanonicalizer#canonicalize}. Before
     * gatekeeper 1.6.0 the response was unsigned and its integrity rested on
     * TLS alone.
     */
    public boolean verifyConfirmation(IssuanceConfirmResponse confirmation) {
        if (confirmation == null) {
            log.warn("ReceiptVerifier: null confirmation response");
            return false;
        }
        return verifySigned("confirmation", confirmation.getVerificationId(), confirmation.getSignature(),
                confirmation.getSigningCertificate(), () -> ConfirmationCanonicalizer.canonicalize(confirmation));
    }

    private boolean verifySigned(String kind, String verificationId, String signatureBase64,
            String signingCertificatePem, java.util.function.Supplier<byte[]> canonical) {
        if (signatureBase64 == null || signatureBase64.isBlank()) {
            log.warn("ReceiptVerifier: missing signature on {} verificationId={}", kind, verificationId);
            return false;
        }
        if (signingCertificatePem == null || signingCertificatePem.isBlank()) {
            log.warn("ReceiptVerifier: missing signingCertificate on {} verificationId={}", kind, verificationId);
            return false;
        }

        // 1. Parse the signing certificate the message advertises.
        X509Certificate advertisedCert;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            advertisedCert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(signingCertificatePem.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            log.warn("ReceiptVerifier: signingCertificate did not parse as X.509: {}", e.getMessage());
            return false;
        }

        // 2. The advertised certificate's public key must be in the registry.
        String fp = GatekeeperKeyRegistry.fingerprintHex(advertisedCert.getPublicKey());
        Optional<X509Certificate> trusted = registry.findByFingerprint(fp);
        if (trusted.isEmpty()) {
            log.warn("ReceiptVerifier: {} advertises untrusted gatekeeper key {} (verificationId={})",
                    kind, fp, verificationId);
            return false;
        }

        // 3. The signature must verify over the canonical bytes.
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException e) {
            log.warn("ReceiptVerifier: signature is not valid base64: {}", e.getMessage());
            return false;
        }
        try {
            PublicKey trustedKey = trusted.get().getPublicKey();
            Signature sig = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);
            sig.initVerify(trustedKey);
            sig.update(canonical.get());
            if (!sig.verify(signatureBytes)) {
                log.warn("ReceiptVerifier: {} signature did not verify under registered gatekeeper key {} "
                        + "(verificationId={})", kind, fp, verificationId);
                return false;
            }
        } catch (Exception e) {
            log.warn("ReceiptVerifier: {} signature verification raised exception: {}", kind, e.getMessage());
            return false;
        }
        return true;
    }
}
