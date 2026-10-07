package eu.gillstrom.hsm.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.hsm.testsupport.TestPki;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyPolicyTest {

    private static KeyPair rsa4096;

    @BeforeAll
    static void generateRsa4096() throws Exception {
        rsa4096 = TestPki.newRsaKeyPair(4096);
    }

    @Test
    @DisplayName("Default policy accepts the real Yubico fixture CSR (RSA-4096, SHA256withRSA)")
    void defaultAcceptsTheRealFixture() throws Exception {
        String csrPem = new ObjectMapper()
                .readTree(Files.readString(Paths.get("examples/yubico/request.json")))
                .get("csr").asText();

        assertThat(violation(KeyPolicy.defaults(), csrPem)).isNull();
    }

    @Test
    @DisplayName("Default policy accepts RSA-4096 signed with SHA512withRSA")
    void defaultAcceptsRsa4096Sha512() throws Exception {
        String csr = TestPki.csrPem(rsa4096, "t", rsa4096.getPrivate(), "SHA512withRSA");

        assertThat(violation(KeyPolicy.defaults(), csr)).isNull();
    }

    @Test
    @DisplayName("Default policy refuses RSA-2048")
    void defaultRefusesRsa2048() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);

        assertThat(violation(KeyPolicy.defaults(), TestPki.csrPem(kp, "t", kp.getPrivate())))
                .contains("RSA-2048");
    }

    @Test
    @DisplayName("Default policy refuses a CSR signed with SHA-1 or MD5")
    void defaultRefusesWeakCsrSignatures() throws Exception {
        assertThat(violation(KeyPolicy.defaults(),
                TestPki.csrPem(rsa4096, "t", rsa4096.getPrivate(), "SHA1withRSA")))
                .contains("SHA1withRSA");
        assertThat(violation(KeyPolicy.defaults(),
                TestPki.csrPem(rsa4096, "t", rsa4096.getPrivate(), "MD5withRSA")))
                .contains("MD5withRSA");
    }

    @Test
    @DisplayName("Default policy refuses EC keys")
    void defaultRefusesEc() throws Exception {
        KeyPair ec = ec("secp256r1");

        assertThat(violation(KeyPolicy.defaults(),
                TestPki.csrPem(ec, "t", ec.getPrivate(), "SHA256withECDSA")))
                .contains("EC-secp256r1");
    }

    @Test
    @DisplayName("An EC curve is accepted only when named in the policy")
    void ecAcceptedWhenNamed() throws Exception {
        KeyPolicy policy = new KeyPolicy("RSA-4096,EC-secp384r1", "SHA384withECDSA");
        KeyPair p384 = ec("secp384r1");
        KeyPair p256 = ec("secp256r1");

        assertThat(violation(policy, TestPki.csrPem(p384, "t", p384.getPrivate(), "SHA384withECDSA")))
                .isNull();
        assertThat(violation(policy, TestPki.csrPem(p256, "t", p256.getPrivate(), "SHA384withECDSA")))
                .contains("EC-secp256r1");
    }

    @Test
    @DisplayName("An empty allow-list is a configuration error")
    void emptyAllowListIsRejected() {
        assertThatThrownBy(() -> new KeyPolicy(" ", "SHA256withRSA"))
                .isInstanceOf(IllegalStateException.class);
    }

    private static String violation(KeyPolicy policy, String csrPem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
            return policy.violation(csr, new JcaPKCS10CertificationRequest(csr).getPublicKey())
                    .orElse(null);
        }
    }

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(curve));
        return g.generateKeyPair();
    }

    @org.junit.jupiter.api.Test
    void weakCsrSignatureAlgorithmsCannotBeConfigured() {
        for (String weak : new String[] {"SHA1withRSA", "sha1withecdsa", "MD5withRSA", "MD2withRSA",
                "SHA256withRSA, SHA1withRSA"}) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> new KeyPolicy("RSA-4096", weak))
                    .as(weak).isInstanceOf(IllegalStateException.class).hasMessageContaining("too weak");
        }
        org.assertj.core.api.Assertions.assertThatCode(() -> new KeyPolicy("RSA-4096", "SHA512withRSA"))
                .doesNotThrowAnyException();
    }
}
