package eu.gillstrom.hsm.controller;

import eu.gillstrom.hsm.testsupport.TestPki;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/** The caller is the leaf of the client chain the TLS handshake established. */
class AttestationControllerCallerTest {

    private static final String ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    @Test
    void theLeafOfTheClientChainIsTheCaller() throws Exception {
        X509Certificate leaf = TestPki.withSubject("C=SE, O=5569743098, CN=1231015932");
        X509Certificate ca = TestPki.withSubject("CN=Swish Customer CA");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(ATTRIBUTE, new X509Certificate[] {leaf, ca});

        assertThat(AttestationController.caller(request)).isSameAs(leaf);
    }

    @Test
    void withoutAClientCertificateThereIsNoCaller() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(AttestationController.caller(request)).isNull();
        request.setAttribute(ATTRIBUTE, new X509Certificate[0]);
        assertThat(AttestationController.caller(request)).isNull();
        request.setAttribute(ATTRIBUTE, "not a chain");
        assertThat(AttestationController.caller(request)).isNull();
    }
}
