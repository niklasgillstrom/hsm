package eu.gillstrom.hsm.gatekeeper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Trust registry of gatekeeper signing certificates. {@link ReceiptVerifier}
 * accepts an {@link VerifyResponse} only if its
 * {@link VerifyResponse#getSigningCertificate() signingCertificate}
 * resolves (by SHA-256 fingerprint of the certificate's public key) to a
 * certificate registered here.
 *
 * <p>This is the analog of pinning HSM root CAs: the financial entity must
 * explicitly trust which gatekeeper certificates count as authoritative
 * supervisory artefacts under DORA Article 6(10) and Regulation (EU) No
 * 1093/2010 Articles 17(6) and 29.
 *
 * <p>Unlike the previous witness-era registry that stored only public keys,
 * this registry stores full {@link X509Certificate} instances. Storing the
 * certificate (not just the bare key) lets supervisors check validity
 * windows, revocation, and issuer DN against the operating NCA's published
 * trust list — material a bare {@link PublicKey} cannot supply.
 *
 * <p>Registration happens at startup from configuration:
 * <ul>
 *   <li>{@code swish.gatekeeper.trusted-keys} — comma-separated list of PEM
 *       certificates whose public keys are accepted as gatekeeper signing
 *       authorities. Empty by default.</li>
 *   <li>{@link #register(X509Certificate)} — programmatic registration,
 *       used by the mock client in test profiles.</li>
 * </ul>
 *
 * <p>If the registry is empty, no receipts will validate. That is the
 * correct fail-closed posture for an unconfigured deployment.
 */
@Component
public class GatekeeperKeyRegistry {

    private static final Logger log = LoggerFactory.getLogger(GatekeeperKeyRegistry.class);

    private final Map<String, X509Certificate> certsByFingerprint = new LinkedHashMap<>();

    public GatekeeperKeyRegistry(
            @Value("${swish.gatekeeper.trusted-keys:}") String trustedKeysPem) {
        if (trustedKeysPem == null || trustedKeysPem.isBlank()) {
            log.warn("GatekeeperKeyRegistry: no trusted gatekeeper certificates configured. "
                    + "All verify-receipts will be rejected. Configure "
                    + "swish.gatekeeper.trusted-keys (comma-separated PEM blocks) for production.");
            return;
        }
        for (String pem : trustedKeysPem.split(",-----END CERTIFICATE-----")) {
            String trimmed = pem.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (!trimmed.endsWith("-----END CERTIFICATE-----")) {
                trimmed = trimmed + "\n-----END CERTIFICATE-----";
            }
            registerFromPem(trimmed);
        }
    }

    /**
     * Register a gatekeeper certificate directly (programmatic, e.g. for tests).
     *
     * @return SHA-256 fingerprint of the certificate's public key, lowercase hex
     */
    public synchronized String register(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate must not be null");
        }
        String fp = fingerprintHex(certificate.getPublicKey());
        certsByFingerprint.put(fp, certificate);
        log.info("GatekeeperKeyRegistry: registered gatekeeper certificate {} "
                + "(public key algorithm {}, subject DN {})",
                fp, certificate.getPublicKey().getAlgorithm(),
                certificate.getSubjectX500Principal().getName());
        return fp;
    }

    /** Register a gatekeeper certificate from PEM text. */
    public synchronized String registerFromPem(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("pem must not be blank");
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
            return register(cert);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to parse trusted gatekeeper certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Lookup a certificate by SHA-256 fingerprint of its public key
     * (lowercase hex, no separators).
     */
    public Optional<X509Certificate> findByFingerprint(String fingerprintHex) {
        if (fingerprintHex == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(certsByFingerprint.get(fingerprintHex.toLowerCase()));
    }

    public Set<String> trustedFingerprints() {
        return Collections.unmodifiableSet(certsByFingerprint.keySet());
    }

    /** SHA-256 fingerprint of a public key's X.509 SubjectPublicKeyInfo, lowercase hex. */
    public static String fingerprintHex(PublicKey publicKey) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            // SHA-256 is JCA-mandatory; this branch should be unreachable.
            throw new IllegalStateException("SHA-256 unavailable on this JVM", e);
        }
    }
}
