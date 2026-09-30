package eu.gillstrom.hsm.issuance;

import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.testsupport.TestPki;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MockIssuanceClientTest {

    private static final String PASSWORD = "mock-ca-test";
    private static final String ALIAS = "mock-ca";

    @TempDir
    Path tempDir;

    @Test
    void configuredCaKeystoreIssuesCertificatesThatChainToThatCa() throws Exception {
        KeyPair caKeyPair = TestPki.newRsaKeyPair(2048);
        X509Certificate caCertificate = TestPki.selfSignedCa(caKeyPair, "Configured Mock CA");
        Path keystore = writeKeystore(caKeyPair, caCertificate, ALIAS);

        MockIssuanceClient client = new MockIssuanceClient(keystore.toString(), PASSWORD, ALIAS);
        client.init();

        X509Certificate leaf = issueFor(client);

        assertThat(client.caCertificate()).isEqualTo(caCertificate);
        assertThat(leaf.getIssuerX500Principal()).isEqualTo(caCertificate.getSubjectX500Principal());
        leaf.verify(caCertificate.getPublicKey());
    }

    @Test
    void configuredCaKeystoreWithoutAliasUsesItsOnlyKeyEntry() throws Exception {
        KeyPair caKeyPair = TestPki.newRsaKeyPair(2048);
        X509Certificate caCertificate = TestPki.selfSignedCa(caKeyPair, "Configured Mock CA Without Alias");
        Path keystore = writeKeystore(caKeyPair, caCertificate, ALIAS);

        MockIssuanceClient client = new MockIssuanceClient(keystore.toString(), PASSWORD, "");
        client.init();

        issueFor(client).verify(caCertificate.getPublicKey());
    }

    @Test
    void configuredCaKeystoreWithUnknownAliasFailsAtStartUp() throws Exception {
        KeyPair caKeyPair = TestPki.newRsaKeyPair(2048);
        X509Certificate caCertificate = TestPki.selfSignedCa(caKeyPair, "Configured Mock CA Unknown Alias");
        Path keystore = writeKeystore(caKeyPair, caCertificate, ALIAS);

        MockIssuanceClient client = new MockIssuanceClient(keystore.toString(), PASSWORD, "no-such-alias");

        assertThatThrownBy(client::init).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void withoutConfiguredKeystoreEachInstanceGeneratesItsOwnCa() throws Exception {
        MockIssuanceClient first = new MockIssuanceClient();
        first.init();
        MockIssuanceClient second = new MockIssuanceClient();
        second.init();

        X509Certificate leaf = issueFor(first);

        leaf.verify(first.caCertificate().getPublicKey());
        assertThat(first.caCertificate().getPublicKey()).isNotEqualTo(second.caCertificate().getPublicKey());
    }

    private X509Certificate issueFor(MockIssuanceClient client) throws Exception {
        KeyPair subjectKeyPair = TestPki.newRsaKeyPair(2048);
        CertificateRequest request = new CertificateRequest();
        request.setCsr(TestPki.csrPem(subjectKeyPair, "mock-subject", subjectKeyPair.getPrivate()));

        IssuedCertificate issued = client.issue(request, "verification-id");

        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(issued.certificatePem().getBytes(StandardCharsets.US_ASCII)));
        assertThat(leaf.getPublicKey()).isEqualTo(subjectKeyPair.getPublic());
        assertThat(issued.verifyReceiptId()).isEqualTo("verification-id");
        return leaf;
    }

    private Path writeKeystore(KeyPair keyPair, X509Certificate certificate, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), PASSWORD.toCharArray(), new Certificate[] {certificate});
        Path file = tempDir.resolve(alias + ".p12");
        try (OutputStream out = Files.newOutputStream(file)) {
            keyStore.store(out, PASSWORD.toCharArray());
        }
        return file;
    }
}
