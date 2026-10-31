package eu.gillstrom.hsm.verification;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The application started with {@code swish.trust-anchors.yubico} naming a
 * test root: the YubicoVerifier bean, the one AttestationService is built
 * with, starts from that root. A test-PKI attestation verifies, the real
 * YubiHSM 2 fixture does not, and every other verifier keeps its pinned
 * anchor.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(properties = {
        "swish.gatekeeper.mode=mock",
        "swish.issuance.mode=mock",
        "swish.signatory-rights.mode=fail-closed"
})
class TrustAnchorOverrideWiringTest {

    private static KeyPair rootKeys;
    private static X509Certificate root;
    private static Path rootFile;

    @DynamicPropertySource
    static void yubicoOverride(DynamicPropertyRegistry registry) throws Exception {
        rootKeys = TrustAnchorsTest.rsa();
        root = TrustAnchorsTest.certificate("CN=Wiring Test Root", rootKeys.getPublic(), "CN=Wiring Test Root",
                rootKeys.getPrivate(), true);
        rootFile = Files.createTempDirectory("hsm-trust-anchor-wiring").resolve("yubico-root.pem");
        Files.writeString(rootFile, TrustAnchorsTest.pem("CERTIFICATE", root.getEncoded()));
        registry.add("swish.trust-anchors.yubico", rootFile::toString);
    }

    @Autowired
    private ApplicationContext context;

    @Test
    void theYubicoVerifierBeanStartsFromTheOperatorsFile() throws Exception {
        assertThat(context.getBeansOfType(YubicoVerifier.class)).hasSize(1);
        YubicoVerifier bean = context.getBean(YubicoVerifier.class);
        assertThat(bean.rootCa()).isEqualTo(root);

        KeyPair attested = TrustAnchorsTest.rsa();
        YubicoVerifier.YubicoAttestationResult test = bean.verifyYubicoAttestation(
                TrustAnchorsTest.yubicoChain(rootKeys.getPrivate(), root, attested.getPublic()), attested.getPublic());
        assertThat(test.getErrors()).isEmpty();
        assertThat(test.isValid()).isTrue();

        JsonNode fixture = TrustAnchorsTest.fixture("/fixtures/yubico/request.json");
        PublicKey realKey = TrustAnchorsTest.csrKey(fixture.get("csr").asText());
        YubicoVerifier.YubicoAttestationResult real = bean.verifyYubicoAttestation(
                TrustAnchorsTest.texts(fixture.get("attestationCertChain")), realKey);
        assertThat(real.isChainValid()).isFalse();
        assertThat(real.isValid()).isFalse();

        TrustAnchors.ActiveAnchor yubico = context.getBean(TrustAnchors.class).active(TrustAnchors.YUBICO);
        assertThat(yubico.origin()).isEqualTo(TrustAnchors.ORIGIN_OVERRIDE);
        assertThat(yubico.path()).isEqualTo(rootFile.toAbsolutePath().normalize().toString());
        assertThat(yubico.sha256()).containsExactly(TrustAnchors.fingerprint(root.getEncoded()));
    }

    @Test
    void everyOtherVerifierBeanKeepsItsPinnedAnchor() {
        assertThat(context.getBean(SecurosysVerifier.class).rootCa()).isEqualTo(new SecurosysVerifier().rootCa());
        assertThat(context.getBean(AzureHsmVerifier.class).marvellRoots())
                .containsExactlyElementsOf(MarvellAttestation.marvellRoots());
        assertThat(context.getBean(GoogleCloudHsmVerifier.class).ownerRoot())
                .isEqualTo(new GoogleCloudHsmVerifier().ownerRoot());
        assertThat(context.getBean(ThalesLunaVerifier.class).rootKey()).isEqualTo(new ThalesLunaVerifier().rootKey());
        assertThat(context.getBean(TrustAnchors.class).all())
                .filteredOn(a -> !a.anchor().equals(TrustAnchors.YUBICO))
                .allMatch(a -> a.origin().equals(TrustAnchors.ORIGIN_PINNED));
    }
}
