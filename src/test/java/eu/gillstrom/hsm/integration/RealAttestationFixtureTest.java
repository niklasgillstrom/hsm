package eu.gillstrom.hsm.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import eu.gillstrom.hsm.testsupport.TestPki;
import eu.gillstrom.hsm.verification.SecurosysVerifier;
import eu.gillstrom.hsm.verification.YubicoVerifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end verifier tests against real attestation fixtures produced by
 * the reference hardware. See {@code examples/README.md} for fixture
 * provenance and the reproducibility contract.
 *
 * <p>These tests prove two things that the synthetic {@code TestPki}-based tests
 * cannot prove on their own:
 * <ol>
 *   <li><b>Happy path</b>: a real attestation produced by a real Securosys/Yubico
 *       device, verified against the pinned vendor root, returns {@code valid=true}
 *       with the expected attested attributes.</li>
 *   <li><b>Binding step</b>: substituting a different CSR public key against the
 *       same real attestation chain causes {@code publicKeyMatch=false} and the
 *       overall result to be {@code valid=false}. This is what prevents an
 *       attacker from re-using a stolen attestation for a software-held key.</li>
 * </ol>
 *
 * <p>The fixtures live under {@code examples/<vendor>/} at the repository root.
 * If they are missing (e.g., a fork that did not pull the example data), the
 * happy-path tests are skipped via {@link EnabledIf}; the negative tests are
 * skipped only if the fixture itself is missing because they re-use the real
 * attestation chain to demonstrate that the binding fails for the wrong CSR.
 */
class RealAttestationFixtureTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Path YUBICO_REQUEST = Paths.get("examples/yubico/request.json");
    private static final Path YUBICO_EXPECTED = Paths.get("examples/yubico/expected.json");
    private static final Path SECUROSYS_REQUEST = Paths.get("examples/securosys/request.json");
    private static final Path SECUROSYS_EXPECTED = Paths.get("examples/securosys/expected.json");

    static boolean yubicoFixturePresent() {
        return Files.exists(YUBICO_REQUEST) && Files.exists(YUBICO_EXPECTED);
    }

    static boolean securosysFixturePresent() {
        return Files.exists(SECUROSYS_REQUEST) && Files.exists(SECUROSYS_EXPECTED);
    }

    // ------------------------------------------------------------------ Yubico

    @Test
    @EnabledIf("yubicoFixturePresent")
    void yubicoFixtureHappyPath() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(YUBICO_REQUEST));
        JsonNode exp = MAPPER.readTree(Files.readString(YUBICO_EXPECTED));

        List<String> chain = readPemList(req.get("attestationCertChain"));
        PublicKey csrPublicKey = parseCsrPublicKey(req.get("csr").asText());

        YubicoVerifier verifier = new YubicoVerifier();
        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(chain, csrPublicKey);

        // Assertions sourced from the captured production response.
        assertThat(r.isChainValid())
                .as("chain should anchor at the pinned Yubico Root CA")
                .isEqualTo(exp.get("attestationChainValid").asBoolean());
        assertThat(r.isPublicKeyMatch())
                .as("attested public key must match CSR public key")
                .isEqualTo(exp.get("publicKeyMatch").asBoolean());
        assertThat(r.getKeyOrigin())
                .as("attested keyOrigin")
                .isEqualTo(exp.get("keyOrigin").asText());
        assertThat(r.isKeyExportable())
                .as("attested keyExportable")
                .isEqualTo(exp.get("keyExportable").asBoolean());
        assertThat(r.isValid())
                .as("overall attestation result")
                .isEqualTo(exp.get("valid").asBoolean());
        assertThat(r.getDeviceSerial())
                .as("device serial extracted from per-device attestation CA subject")
                .isEqualTo(exp.get("hsmSerialNumber").asText());
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void yubicoFixtureRejectsCsrForDifferentKey() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(YUBICO_REQUEST));
        List<String> chain = readPemList(req.get("attestationCertChain"));

        // Replace the CSR's public key with a synthetic one. The attestation
        // chain itself is unchanged and still validates; only the CSR-binding
        // step should fail.
        KeyPair other = TestPki.newRsaKeyPair(2048);

        YubicoVerifier verifier = new YubicoVerifier();
        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(chain, other.getPublic());

        assertThat(r.isChainValid())
                .as("chain itself is real and still validates")
                .isTrue();
        assertThat(r.isPublicKeyMatch())
                .as("CSR for wrong key must not bind to attested key")
                .isFalse();
        assertThat(r.isValid())
                .as("overall result must be invalid when binding fails")
                .isFalse();
    }

    // -------------------------------------------------------------- Securosys

    @Test
    @EnabledIf("securosysFixturePresent")
    void securosysFixtureHappyPath() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(SECUROSYS_REQUEST));
        JsonNode exp = MAPPER.readTree(Files.readString(SECUROSYS_EXPECTED));

        String xmlBase64 = req.get("attestationData").asText();
        String sigBase64 = req.get("attestationSignature").asText();
        List<String> chain = readPemList(req.get("attestationCertChain"));
        PublicKey csrPublicKey = parseCsrPublicKey(req.get("csr").asText());

        SecurosysVerifier verifier = new SecurosysVerifier();
        SecurosysVerifier.SecurosysAttestationResult r =
                verifier.verifySecurosysAttestation(xmlBase64, sigBase64, chain, csrPublicKey);

        assertThat(r.isChainValid())
                .as("chain should anchor at the pinned Securosys Primus Root CA")
                .isEqualTo(exp.get("attestationChainValid").asBoolean());
        assertThat(r.isSignatureValid())
                .as("XML signature should verify under attested public key")
                .isTrue();
        assertThat(r.isPublicKeyMatch())
                .as("attested public key (XML public_key element) must match CSR")
                .isEqualTo(exp.get("publicKeyMatch").asBoolean());
        assertThat(r.isExtractable())
                .as("attested key must NOT be extractable")
                .isFalse();
        assertThat(r.isNeverExtractable())
                .as("attested key must be never_extractable")
                .isTrue();
        assertThat(r.isSensitive())
                .as("attested key must be sensitive")
                .isTrue();
        assertThat(r.isAlwaysSensitive())
                .as("attested key must be always_sensitive")
                .isTrue();
        assertThat(r.isValid())
                .as("overall attestation result")
                .isEqualTo(exp.get("valid").asBoolean());
        assertThat(r.getHsmSerialNumber())
                .as("HSM serial extracted from issuing CA subject CN")
                .isEqualTo(exp.get("hsmSerialNumber").asText());
    }

    @Test
    @EnabledIf("securosysFixturePresent")
    void securosysFixtureRejectsCsrForDifferentKey() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(SECUROSYS_REQUEST));
        String xmlBase64 = req.get("attestationData").asText();
        String sigBase64 = req.get("attestationSignature").asText();
        List<String> chain = readPemList(req.get("attestationCertChain"));

        KeyPair other = TestPki.newRsaKeyPair(2048);

        SecurosysVerifier verifier = new SecurosysVerifier();
        SecurosysVerifier.SecurosysAttestationResult r =
                verifier.verifySecurosysAttestation(xmlBase64, sigBase64, chain, other.getPublic());

        assertThat(r.isChainValid()).as("chain itself is real and still validates").isTrue();
        assertThat(r.isSignatureValid()).as("XML signature is real and still verifies").isTrue();
        assertThat(r.isPublicKeyMatch())
                .as("CSR for wrong key must not bind to attested key")
                .isFalse();
        assertThat(r.isValid())
                .as("overall result must be invalid when binding fails")
                .isFalse();
    }

    // ----------------------------------------------------------------- helpers

    private static List<String> readPemList(JsonNode arr) {
        List<String> out = new ArrayList<>(arr.size());
        for (JsonNode n : arr) {
            out.add(n.asText());
        }
        return out;
    }

    private static PublicKey parseCsrPublicKey(String csrPem) throws Exception {
        // Strip PEM armour and decode body.
        String body = csrPem
                .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(body);
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(der);
        return new JcaPKCS10CertificationRequest(csr).getPublicKey();
    }
}
