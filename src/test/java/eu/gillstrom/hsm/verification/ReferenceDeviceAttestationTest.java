package eu.gillstrom.hsm.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.StringReader;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The verifiers against real attestations from the reference devices (the
 * same fixtures as gatekeeper's {@code src/test/resources/fixtures}): an
 * RSA-4096 key on a YubiHSM 2 (serial 20783176) and on a Securosys Primus
 * (serial 18386101).
 */
class ReferenceDeviceAttestationTest {

    private static JsonNode fixture(String vendor) throws Exception {
        try (InputStream in = ReferenceDeviceAttestationTest.class
                .getResourceAsStream("/fixtures/" + vendor + "/request.json")) {
            return new ObjectMapper().readTree(in);
        }
    }

    private static PublicKey csrKey(JsonNode fixture) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(fixture.get("csr").asText()))) {
            var csr = (PKCS10CertificationRequest) parser.readObject();
            return new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo());
        }
    }

    private static List<String> chain(JsonNode fixture) {
        List<String> chain = new ArrayList<>();
        fixture.get("attestationCertChain").forEach(pem -> chain.add(pem.asText()));
        return chain;
    }

    @Test
    void referenceYubiHsm2AttestsItsRsa4096Key() throws Exception {
        JsonNode f = fixture("yubico");
        PublicKey key = csrKey(f);
        assertThat(((RSAPublicKey) key).getModulus().bitLength()).isEqualTo(4096);

        var r = new YubicoVerifier().verifyYubicoAttestation(chain(f), key);

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.isKeyExportable()).isFalse();
        assertThat(r.getDeviceSerial()).isEqualTo("20783176");
    }

    @Test
    void referencePrimusAttestsItsRsa4096Key() throws Exception {
        JsonNode f = fixture("securosys");
        PublicKey key = csrKey(f);
        assertThat(((RSAPublicKey) key).getModulus().bitLength()).isEqualTo(4096);

        var r = new SecurosysVerifier().verifySecurosysAttestation(f.get("attestationData").asText(),
                f.get("attestationSignature").asText(), chain(f), key);

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).isTrue();
        assertThat(r.isChainValid()).isTrue();
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.isExtractable()).isFalse();
        assertThat(r.isNeverExtractable()).isTrue();
    }

    @Test
    void anotherKeyDoesNotMatchEitherAttestation() throws Exception {
        PublicKey primusKey = csrKey(fixture("securosys"));
        PublicKey yubiKey = csrKey(fixture("yubico"));
        assertThat(new YubicoVerifier().verifyYubicoAttestation(chain(fixture("yubico")), primusKey)
                .isPublicKeyMatch()).isFalse();
        JsonNode s = fixture("securosys");
        assertThat(new SecurosysVerifier().verifySecurosysAttestation(s.get("attestationData").asText(),
                s.get("attestationSignature").asText(), chain(s), yubiKey).isPublicKeyMatch()).isFalse();
    }
}
