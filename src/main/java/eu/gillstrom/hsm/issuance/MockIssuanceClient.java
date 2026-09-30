package eu.gillstrom.hsm.issuance;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import eu.gillstrom.hsm.model.CertificateRequest;

import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Demonstration {@link IssuanceClient} that issues certificates against an
 * in-process test CA. Selected via {@code swish.issuance.mode=mock} (the only
 * mode shipped in this reference repo).
 *
 * <p>NOT a production CA. The CA key pair is regenerated on every startup
 * unless {@code swish.issuance.mock.ca-keystore} names a PKCS12 keystore, in
 * which case the CA key and certificate are loaded from it so that a local
 * gatekeeper can be configured to trust the issuing CA. Issued certificates
 * do not chain to any real Swish CA root and have no
 * trust beyond demonstrating the verify→issue→confirm plumbing. A production
 * deployment must replace this with an integration against the real Getswish
 * CA, which is operated externally by Getswish AB.
 *
 * <p>Issued certificates carry the gatekeeper's {@code verificationId} in
 * {@link IssuedCertificate#verifyReceiptId()} so the issuance is auditably
 * bound to a specific supervisory authorisation.
 */
@Component
@ConditionalOnProperty(name = "swish.issuance.mode", havingValue = "mock", matchIfMissing = true)
public class MockIssuanceClient implements IssuanceClient {

    private static final Logger log = LoggerFactory.getLogger(MockIssuanceClient.class);

    private final String caKeystore;
    private final String caKeystorePassword;
    private final String caAlias;

    private KeyPair caKeyPair;
    private X509Certificate caCert;

    public MockIssuanceClient() {
        this("", "", "");
    }

    @Autowired
    public MockIssuanceClient(
            @Value("${swish.issuance.mock.ca-keystore:}") String caKeystore,
            @Value("${swish.issuance.mock.ca-keystore-password:}") String caKeystorePassword,
            @Value("${swish.issuance.mock.ca-alias:}") String caAlias) {
        this.caKeystore = caKeystore == null ? "" : caKeystore.trim();
        this.caKeystorePassword = caKeystorePassword == null ? "" : caKeystorePassword;
        this.caAlias = caAlias == null ? "" : caAlias.trim();
    }

    @PostConstruct
    public void init() throws Exception {
        if (!caKeystore.isEmpty()) {
            loadCa();
            log.warn("MockIssuanceClient is active: certificates are issued against the "
                    + "test CA loaded from {} (subject {}). NOT for production.",
                    caKeystore, caCert.getSubjectX500Principal().getName());
            return;
        }
        log.warn("MockIssuanceClient is active: certificates are issued against an "
                + "in-process test CA whose root is regenerated on every startup. "
                + "NOT for production. Replace with an integration against the real "
                + "Getswish CA before going live.");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        caKeyPair = kpg.generateKeyPair();
        caCert = buildCa(caKeyPair);
    }

    public X509Certificate caCertificate() {
        return caCert;
    }

    private void loadCa() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = caKeystorePassword.toCharArray();
        try (InputStream in = Files.newInputStream(Path.of(caKeystore))) {
            keyStore.load(in, password);
        }
        String alias = caAlias;
        if (alias.isEmpty()) {
            for (String candidate : java.util.Collections.list(keyStore.aliases())) {
                if (keyStore.isKeyEntry(candidate)) {
                    alias = candidate;
                    break;
                }
            }
        }
        if (alias.isEmpty() || !keyStore.isKeyEntry(alias)) {
            throw new IllegalStateException("swish.issuance.mock.ca-keystore " + caKeystore
                    + " holds no private key entry" + (caAlias.isEmpty() ? "" : " under alias " + caAlias));
        }
        Key key = keyStore.getKey(alias, password);
        if (!(key instanceof PrivateKey privateKey)) {
            throw new IllegalStateException("Entry " + alias + " in " + caKeystore + " is not a private key");
        }
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        caKeyPair = new KeyPair(certificate.getPublicKey(), privateKey);
        caCert = certificate;
    }

    @Override
    public IssuedCertificate issue(CertificateRequest request, String verifyReceiptId) {
        try {
            PublicKey csrPublicKey = parseCsrPublicKey(request.getCsr());
            X500Name subject = new X500Name("CN=mock-issued, O=hsm, L=test");
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis())
                    .shiftLeft(16).or(BigInteger.valueOf(new SecureRandom().nextInt(65535)));
            Instant now = Instant.now();
            Date notBefore = Date.from(now.minusSeconds(60));
            Date notAfter = Date.from(now.plusSeconds(86400L * 365));

            JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                    caCert, serial, notBefore, notAfter, subject, csrPublicKey);
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKeyPair.getPrivate());
            X509Certificate leaf = new JcaX509CertificateConverter()
                    .getCertificate(b.build(signer));

            String pem = toPem(leaf);

            return new IssuedCertificate(
                    pem,
                    leaf.getIssuerX500Principal().getName(),
                    leaf.getSubjectX500Principal().getName(),
                    leaf.getNotBefore().toInstant(),
                    leaf.getNotAfter().toInstant(),
                    "mock-" + UUID.randomUUID(),
                    verifyReceiptId);
        } catch (Exception e) {
            throw new IssuanceException("Mock issuance failed: " + e.getMessage(), e);
        }
    }

    private static X509Certificate buildCa(KeyPair kp) throws Exception {
        X500Name subject = new X500Name("CN=MockSwishCA-test, O=hsm, L=test");
        Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86400_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(signer));
    }

    private static PublicKey parseCsrPublicKey(String pem) throws Exception {
        String body = pem
                .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(body);
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(der);
        return new JcaPKCS10CertificationRequest(csr).getPublicKey();
    }

    private static String toPem(X509Certificate cert) throws Exception {
        StringWriter w = new StringWriter();
        w.append("-----BEGIN CERTIFICATE-----\n");
        w.append(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded()));
        w.append("\n-----END CERTIFICATE-----\n");
        return w.toString();
    }
}
