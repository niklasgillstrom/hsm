package eu.gillstrom.hsm.controller;

import eu.gillstrom.hsm.testsupport.TestPki;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The transport certificate of a real mTLS connection reaches CallerPolicy:
 * the server asks for a client certificate, as a deployment does
 * ({@code server.ssl.client-auth=need}), and the request's errors show whether
 * the certificate was compared with the request.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CallerCertificateWiringTest {

    private static final char[] PW = "changeit".toCharArray();

    private static final KeyPair SERVER_KEY;
    private static final X509Certificate SERVER_CERT;
    private static final KeyPair OWN_KEY;
    private static final X509Certificate OWN_CERT;
    private static final KeyPair OTHER_KEY;
    private static final X509Certificate OTHER_CERT;
    private static final Path DIR;
    private static final String CSR;

    static {
        try {
            SERVER_KEY = TestPki.newRsaKeyPair(2048);
            SERVER_CERT = selfSigned(SERVER_KEY, new X500Name("CN=localhost"), true);
            OWN_KEY = TestPki.newRsaKeyPair(2048);
            OWN_CERT = selfSigned(OWN_KEY, new X500Name("C=SE, O=5569743098, CN=1231015932"), false);
            OTHER_KEY = TestPki.newRsaKeyPair(2048);
            OTHER_CERT = selfSigned(OTHER_KEY, new X500Name("C=SE, O=5561234567, CN=1239999999"), false);
            DIR = Files.createTempDirectory("caller-mtls");
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("server", SERVER_KEY.getPrivate(), PW, new Certificate[] {SERVER_CERT});
            store(ks, DIR.resolve("server.p12"));
            KeyStore ts = KeyStore.getInstance("PKCS12");
            ts.load(null, null);
            ts.setCertificateEntry("own", OWN_CERT);
            ts.setCertificateEntry("other", OTHER_CERT);
            store(ts, DIR.resolve("clients.p12"));
            KeyPair csrKey = TestPki.newRsaKeyPair(4096);
            CSR = TestPki.csrPem(csrKey, "Test", csrKey.getPrivate(), "SHA512withRSA");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void tls(DynamicPropertyRegistry r) {
        r.add("server.ssl.enabled", () -> "true");
        r.add("server.ssl.key-store", () -> DIR.resolve("server.p12").toUri().toString());
        r.add("server.ssl.key-store-password", () -> new String(PW));
        r.add("server.ssl.key-store-type", () -> "PKCS12");
        r.add("server.ssl.trust-store", () -> DIR.resolve("clients.p12").toUri().toString());
        r.add("server.ssl.trust-store-password", () -> new String(PW));
        r.add("server.ssl.trust-store-type", () -> "PKCS12");
        r.add("server.ssl.client-auth", () -> "need");
    }

    @LocalServerPort
    private int port;

    @Test
    void theCompanysOwnCertificateIsBoundAndAnotherIsNot() throws Exception {
        String own = post(OWN_KEY, OWN_CERT);
        String other = post(OTHER_KEY, OTHER_CERT);

        // The request fails on its (absent) BankID signature either way; what
        // differs is whether the caller matched it.
        assertThat(own).contains("BankID").doesNotContain("CALLER_");
        assertThat(other).contains("CALLER_NOT_BOUND").doesNotContain("CALLER_CERTIFICATE_MISSING");
    }

    private String post(KeyPair key, X509Certificate cert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", key.getPrivate(), PW, new Certificate[] {cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, PW);
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("server", SERVER_CERT);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        String body = "{\"csr\":\"" + CSR.replace("\n", "\\n") + "\","
                + "\"bankIdSignatureResponse\":\"x\",\"bankIdOcspResponse\":\"x\","
                + "\"organisationNumber\":\"5569743098\",\"swishNumber\":\"1231015932\","
                + "\"certificateType\":\"TRANSPORT\"}";
        HttpClient client = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).sslContext(ssl).build();
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(
                        URI.create("https://localhost:" + port + "/api/v1/attestation/verify"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        return response.body();
    }

    private static X509Certificate selfSigned(KeyPair kp, X500Name subject, boolean localhost) throws Exception {
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(now),
                new Date(now - 60_000L), new Date(now + 3600_000L), subject, kp.getPublic());
        if (localhost) {
            b.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }

    private static void store(KeyStore ks, Path file) throws Exception {
        try (OutputStream out = Files.newOutputStream(file)) {
            ks.store(out, PW);
        }
    }
}
