package eu.gillstrom.hsm.util;

import eu.gillstrom.hsm.testsupport.TestPki;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CsrsTest {

    private static final KeyPair KP;
    private static final String PEM;

    static {
        try {
            KP = TestPki.newRsaKeyPair(2048);
            PEM = TestPki.csrPem(KP, "Test", KP.getPrivate());
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static String body() {
        return PEM.replace("-----BEGIN CERTIFICATE REQUEST-----", "").replace("-----END CERTIFICATE REQUEST-----", "").trim();
    }

    @Test
    void thePemLabelsAndBareBase64AllReadTheSameDer() throws Exception {
        byte[] der = Csrs.der(PEM);
        assertThat(Csrs.der("-----BEGIN NEW CERTIFICATE REQUEST-----\r\n" + body()
                + "\r\n-----END NEW CERTIFICATE REQUEST-----\r\n")).isEqualTo(der);
        assertThat(Csrs.der(body())).isEqualTo(der);
        assertThat(Csrs.der("  \n" + PEM + "\n ")).isEqualTo(der);
        assertThat(Csrs.parse(PEM).getEncoded()).isEqualTo(der);
        assertThat(Csrs.publicKey(PEM).getEncoded()).isEqualTo(KP.getPublic().getEncoded());
        assertThat(Csrs.publicKey(PEM).getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void anythingButOneBlockIsRefused() {
        assertThatThrownBy(() -> Csrs.der(PEM + "\n" + PEM)).hasMessageContaining("exactly one PEM");
        assertThatThrownBy(() -> Csrs.der(PEM + "trailing")).hasMessageContaining("exactly one PEM");
        assertThatThrownBy(() -> Csrs.der("leading" + PEM)).hasMessageContaining("exactly one PEM");
        assertThatThrownBy(() -> Csrs.der("-----BEGIN NEW CERTIFICATE REQUEST-----\n" + body()
                + "\n-----END CERTIFICATE REQUEST-----")).hasMessageContaining("labels");
        assertThatThrownBy(() -> Csrs.der("-----BEGIN CERTIFICATE REQUEST-----\n" + body()
                + "\n-----END NEW CERTIFICATE REQUEST-----")).hasMessageContaining("labels");
        assertThatThrownBy(() -> Csrs.der("-----BEGIN CERTIFICATE-----\n" + body() + "\n-----END CERTIFICATE-----"))
                .hasMessageContaining("exactly one PEM");
        assertThatThrownBy(() -> Csrs.der(" ")).hasMessageContaining("empty");
        assertThatThrownBy(() -> Csrs.der(null)).hasMessageContaining("empty");
        assertThatThrownBy(() -> Csrs.der("not*base64")).hasMessageContaining("not base64");
        assertThatThrownBy(() -> Csrs.parse(Base64.getEncoder().encodeToString(new byte[] {1, 2, 3})))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("does not parse");
        assertThatThrownBy(() -> Csrs.parse("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anEcKeyIsReadAsEc() throws Exception {
        var g = java.security.KeyPairGenerator.getInstance("EC");
        g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair ec = g.generateKeyPair();
        String pem = TestPki.csrPem(ec, "EC", ec.getPrivate(), "SHA256withECDSA");
        assertThat(Csrs.publicKey(pem).getAlgorithm()).isEqualTo("EC");
        assertThat(Csrs.publicKey(pem).getEncoded()).isEqualTo(ec.getPublic().getEncoded());
    }
}
