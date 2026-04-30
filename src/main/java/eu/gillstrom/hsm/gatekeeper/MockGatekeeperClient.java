package eu.gillstrom.hsm.gatekeeper;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * In-process {@link GatekeeperClient} that signs receipts with an ephemeral
 * RSA key pair generated at startup. Selected via
 * {@code swish.gatekeeper.mode=mock}.
 *
 * <p>For demonstration and testing only. Auto-registers its self-signed
 * certificate with the shared {@link GatekeeperKeyRegistry} so that
 * {@link ReceiptVerifier} accepts the receipts it produces. A production
 * deployment must replace this with a real gatekeeper run by the operating
 * National Competent Authority and configure
 * {@code swish.gatekeeper.mode=http} pointing at that gatekeeper.
 *
 * <p>Receipts are unconditionally {@code compliant=true}: this implementation
 * does NOT re-run HSM-attestation verification. Its purpose is solely to
 * demonstrate the receipt format and the verify→issue→confirm plumbing.
 *
 * <p>The mock confirm step always returns
 * {@code RegistryStatus.VERIFIED_AND_ISSUED} when the public-key match is
 * computed against the issued certificate (or
 * {@code REJECTED_NOT_ISSUED} when {@code issued=false}). It does NOT
 * implement the anomaly states — those are gatekeeper-side concerns.
 */
@Component
@ConditionalOnProperty(name = "swish.gatekeeper.mode", havingValue = "mock")
public class MockGatekeeperClient implements GatekeeperClient {

    private static final Logger log = LoggerFactory.getLogger(MockGatekeeperClient.class);

    private final GatekeeperKeyRegistry registry;
    private KeyPair keyPair;
    private X509Certificate signingCertificate;
    private String signingCertificatePem;
    private String fingerprint;

    /** Per-verificationId memo of (publicKey fingerprint) so confirm can check the loop. */
    private final Map<String, String> approvedKeyByVerificationId = new LinkedHashMap<>();

    /** Per-verificationId memo of confirmation nonce. Mirrors the gatekeeper's
     *  Step-7 replay-binding: a confirm whose submitted nonce does not match the
     *  one bound here at verify time is rejected. */
    private final Map<String, String> approvedNonceByVerificationId = new LinkedHashMap<>();

    private static final java.security.SecureRandom NONCE_RNG = new java.security.SecureRandom();

    private static String generateNonce() {
        byte[] bytes = new byte[32];
        NONCE_RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public MockGatekeeperClient(GatekeeperKeyRegistry registry) {
        if (registry == null) {
            throw new IllegalArgumentException("registry must not be null");
        }
        this.registry = registry;
    }

    @PostConstruct
    public void init() throws Exception {
        log.warn("MockGatekeeperClient is active: receipts are signed by an ephemeral, "
                + "in-process RSA key. NOT for production. Replace with "
                + "swish.gatekeeper.mode=http pointing at a real NCA-operated gatekeeper.");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        this.keyPair = kpg.generateKeyPair();
        this.signingCertificate = buildSelfSignedCertificate(keyPair);
        this.signingCertificatePem = toPem(signingCertificate);
        this.fingerprint = registry.register(signingCertificate);
        log.info("MockGatekeeperClient: registered ephemeral signing cert fingerprint {}", fingerprint);
    }

    @Override
    public VerifyResponse verify(VerifyRequest request) throws GatekeeperException {
        if (request == null) {
            throw new GatekeeperException("verify called with null request");
        }
        try {
            Instant verifiedAt = Instant.now();
            String verificationId = UUID.randomUUID().toString();
            String confirmationNonce = generateNonce();

            String publicKeyFingerprint = fingerprintOfPublicKeyPem(request.getPublicKey());
            VerifyResponse.KeyProperties keyProperties = VerifyResponse.KeyProperties.builder()
                    .generatedOnDevice(true)
                    .exportable(false)
                    .attestationChainValid(true)
                    .publicKeyMatchesAttestation(true)
                    .build();
            VerifyResponse.DoraCompliance dora = VerifyResponse.DoraCompliance.builder()
                    .article5_2b(true)
                    .article6_10(true)
                    .article9_3c(true)
                    .article9_3d(true)
                    .article9_4d(true)
                    .article28_1a(true)
                    .summary("Mock gatekeeper: cryptographic evidence accepted (NOT a real determination)")
                    .build();

            VerifyResponse unsigned = VerifyResponse.builder()
                    .verificationId(verificationId)
                    .confirmationNonce(confirmationNonce)
                    .compliant(true)
                    .verificationTimestamp(verifiedAt)
                    .publicKeyFingerprint(publicKeyFingerprint)
                    .publicKeyAlgorithm("RSA")
                    .hsmVendor(request.getHsmVendor())
                    .hsmModel(modelFor(request.getHsmVendor()))
                    .hsmSerialNumber("MOCK-SERIAL")
                    .keyProperties(keyProperties)
                    .doraCompliance(dora)
                    .supplierIdentifier(request.getSupplierIdentifier())
                    .supplierName(request.getSupplierName())
                    .keyPurpose(request.getKeyPurpose())
                    .countryCode(request.getCountryCode())
                    .errors(Collections.emptyList())
                    .warnings(Collections.emptyList())
                    .signingCertificate(signingCertificatePem)
                    .build();

            byte[] canonical = ReceiptCanonicalizer.canonicalize(unsigned);
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(keyPair.getPrivate());
            sig.update(canonical);
            unsigned.setSignature(Base64.getEncoder().encodeToString(sig.sign()));

            approvedKeyByVerificationId.put(verificationId, publicKeyFingerprint);
            approvedNonceByVerificationId.put(verificationId, confirmationNonce);
            return unsigned;
        } catch (Exception e) {
            throw new GatekeeperException(
                    "Mock gatekeeper verify failed: " + e.getMessage(), e);
        }
    }

    @Override
    public IssuanceConfirmResponse confirm(IssuanceConfirmRequest request) throws GatekeeperException {
        if (request == null) {
            throw new GatekeeperException("confirm called with null request");
        }
        String expected = approvedKeyByVerificationId.get(request.getVerificationId());
        String expectedNonce = approvedNonceByVerificationId.get(request.getVerificationId());
        String processedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

        if (expected == null) {
            return IssuanceConfirmResponse.builder()
                    .verificationId(request.getVerificationId())
                    .loopClosed(false)
                    .registryStatus(IssuanceConfirmResponse.RegistryStatus.ANOMALY_UNKNOWN_VERIFICATION)
                    .processedTimestamp(processedAt)
                    .anomalies(List.of("verificationId not found in mock approval registry"))
                    .build();
        }

        // Step-7 replay binding: nonce must match the one bound at verify time.
        String submitted = request.getConfirmationNonce();
        if (expectedNonce == null || submitted == null
                || !java.security.MessageDigest.isEqual(
                        expectedNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        submitted.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            log.warn("MockGatekeeperClient: nonce mismatch on confirm for verificationId={} "
                    + "— possible Step-7 replay attempt", request.getVerificationId());
            throw new GatekeeperException(
                    "Confirmation nonce does not match the nonce bound at verify time "
                  + "for verificationId=" + request.getVerificationId());
        }

        if (!request.isIssued()) {
            return IssuanceConfirmResponse.builder()
                    .verificationId(request.getVerificationId())
                    .loopClosed(true)
                    .publicKeyMatch(null)
                    .expectedPublicKeyFingerprint(expected)
                    .registryStatus(IssuanceConfirmResponse.RegistryStatus.VERIFIED_NOT_ISSUED)
                    .processedTimestamp(processedAt)
                    .anomalies(Collections.emptyList())
                    .build();
        }

        try {
            String actual = fingerprintOfCertificatePublicKey(request.getSigningCertificatePem());
            boolean match = expected.equals(actual);
            return IssuanceConfirmResponse.builder()
                    .verificationId(request.getVerificationId())
                    .loopClosed(match)
                    .publicKeyMatch(match)
                    .expectedPublicKeyFingerprint(expected)
                    .actualPublicKeyFingerprint(actual)
                    .registryStatus(match
                            ? IssuanceConfirmResponse.RegistryStatus.VERIFIED_AND_ISSUED
                            : IssuanceConfirmResponse.RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH)
                    .processedTimestamp(processedAt)
                    .anomalies(match ? Collections.emptyList()
                            : List.of("public key in issued certificate does not match attested public key"))
                    .build();
        } catch (Exception e) {
            throw new GatekeeperException(
                    "Mock gatekeeper confirm failed: " + e.getMessage(), e);
        }
    }

    /** Exposed for tests that need to assert against the mock fingerprint. */
    public String getFingerprint() {
        return fingerprint;
    }

    /** Exposed for tests that need to construct a valid receipt directly. */
    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    /** Exposed for tests that need to sign a custom receipt with the same key. */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    private static String modelFor(String hsmVendor) {
        if (hsmVendor == null) {
            return "Mock HSM";
        }
        return switch (hsmVendor.toUpperCase()) {
            case "YUBICO" -> "YubiHSM 2";
            case "SECUROSYS" -> "Primus HSM";
            case "AZURE" -> "Azure Managed HSM";
            case "GOOGLE" -> "Google Cloud HSM";
            default -> "Mock HSM";
        };
    }

    private static X509Certificate buildSelfSignedCertificate(KeyPair kp) throws Exception {
        X500Name subject = new X500Name(
                "CN=MockGatekeeper-test, O=hsm, L=test");
        Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        var b = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(signer));
    }

    private static String toPem(X509Certificate cert) throws Exception {
        StringWriter w = new StringWriter();
        w.append("-----BEGIN CERTIFICATE-----\n");
        w.append(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded()));
        w.append("\n-----END CERTIFICATE-----\n");
        return w.toString();
    }

    private static String fingerprintOfPublicKeyPem(String pem) throws Exception {
        if (pem == null || pem.isBlank()) {
            return null;
        }
        // Try X.509 SubjectPublicKeyInfo (PEM "PUBLIC KEY") parsing.
        String body = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(body);
        var spec = new java.security.spec.X509EncodedKeySpec(der);
        PublicKey pk = java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
        return GatekeeperKeyRegistry.fingerprintHex(pk);
    }

    private static String fingerprintOfCertificatePublicKey(String pem) throws Exception {
        var cf = java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(pem.getBytes()));
        return GatekeeperKeyRegistry.fingerprintHex(cert.getPublicKey());
    }
}
