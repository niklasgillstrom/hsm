package eu.gillstrom.hsm.verification;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import eu.gillstrom.hsm.testsupport.TestPki;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurosysVerifier}. The pinned Securosys Primus root
 * CA is a production trust anchor, so a throwaway test chain can never PKIX-
 * validate against it; the assertions below encode exactly that expectation.
 */
class SecurosysVerifierTest {

    private SecurosysVerifier verifier;
    private KeyPair attestationKp;
    private List<String> chainPem;
    private byte[] xmlBytes;
    private String xmlBase64;
    private String signatureBase64;

    @BeforeEach
    void setUp() throws Exception {
        verifier = new SecurosysVerifier();

        // Build a throwaway fake vendor PKI: fake-root -> device -> attestation.
        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate fakeRoot = TestPki.selfSignedCa(rootKp, "FAKE-SECUROSYS-ROOT");

        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate deviceCert = TestPki.subordinateCa(
                deviceKp, "FAKE-DEVICE SN: 12345", fakeRoot, rootKp.getPrivate());

        attestationKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = TestPki.endEntity(
                attestationKp, "FAKE-ATTEST-LEAF", deviceCert, deviceKp.getPrivate());

        chainPem = List.of(
                TestPki.toPem(attestCert),
                TestPki.toPem(deviceCert),
                TestPki.toPem(fakeRoot));

        // Minimal Securosys-shape XML. The verifier signs the raw XML bytes
        // (after base64-decoding the xmlBase64 parameter) so we can include
        // the attestation key itself as the attested public_key.
        String pubKeyB64 = Base64.getEncoder().encodeToString(attestationKp.getPublic().getEncoded());
        String xml = "<attestation>"
                + "<public_key>" + pubKeyB64 + "</public_key>"
                + "<extractable>false</extractable>"
                + "<never_extractable>true</never_extractable>"
                + "<sensitive>true</sensitive>"
                + "<always_sensitive>true</always_sensitive>"
                + "</attestation>";
        xmlBytes = xml.getBytes(StandardCharsets.UTF_8);
        xmlBase64 = Base64.getEncoder().encodeToString(xmlBytes);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(attestationKp.getPrivate());
        sig.update(xmlBytes);
        signatureBase64 = Base64.getEncoder().encodeToString(sig.sign());
    }

    @Test
    void fakeChainIsNotRootedAtPinnedSecurosysRoot() {
        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                xmlBase64, signatureBase64, chainPem, attestationKp.getPublic());

        // Fake root != pinned Securosys root — PKIX must reject.
        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.contains("chain"));

        // But the XML signature and public-key match must still succeed — this
        // demonstrates that the chain-rejection is specifically the PKIX call,
        // not an accidental early return.
        assertThat(r.isSignatureValid()).isTrue();
        assertThat(r.isPublicKeyMatch()).isTrue();

        // Overall verdict rolls up chainValid, so it must be false.
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void tamperedSignatureIsRejected() {
        byte[] tampered = Base64.getDecoder().decode(signatureBase64);
        tampered[tampered.length - 1] ^= 0x01;
        String tamperedB64 = Base64.getEncoder().encodeToString(tampered);

        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                xmlBase64, tamperedB64, chainPem, attestationKp.getPublic());

        assertThat(r.isSignatureValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("signature"));
    }

    @Test
    void emptyChainProducesError() {
        SecurosysVerifier.SecurosysAttestationResult r = verifier.verifySecurosysAttestation(
                xmlBase64, signatureBase64, Collections.emptyList(), attestationKp.getPublic());

        assertThat(r.getErrors()).isNotEmpty();
        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("no certificates"));
        assertThat(r.isValid()).isFalse();
    }
}
