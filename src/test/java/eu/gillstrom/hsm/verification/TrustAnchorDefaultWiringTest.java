package eu.gillstrom.hsm.verification;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The application started without {@code swish.trust-anchors.*} (the
 * configuration of {@code ApplicationContextLoadsTest}): every verifier bean
 * holds exactly the anchor its no-argument constructor pins, and the real
 * YubiHSM 2 fixture verifies through the bean as before.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(properties = {
        "swish.gatekeeper.mode=mock",
        "swish.issuance.mode=mock",
        "swish.signatory-rights.mode=fail-closed"
})
class TrustAnchorDefaultWiringTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void everyVerifierBeanHoldsItsPinnedAnchor() throws Exception {
        assertThat(context.getBean(YubicoVerifier.class).rootCa()).isEqualTo(new YubicoVerifier().rootCa());
        assertThat(context.getBean(SecurosysVerifier.class).rootCa()).isEqualTo(new SecurosysVerifier().rootCa());
        assertThat(context.getBean(AzureHsmVerifier.class).marvellRoots())
                .containsExactlyElementsOf(new AzureHsmVerifier().marvellRoots());
        assertThat(context.getBean(MarvellHsmVerifier.class).marvellRoots())
                .containsExactlyElementsOf(new MarvellHsmVerifier().marvellRoots());
        assertThat(context.getBean(GoogleCloudHsmVerifier.class).marvellRoots())
                .containsExactlyElementsOf(new GoogleCloudHsmVerifier().marvellRoots());
        assertThat(context.getBean(GoogleCloudHsmVerifier.class).ownerRoot())
                .isEqualTo(new GoogleCloudHsmVerifier().ownerRoot());
        assertThat(context.getBean(ThalesLunaVerifier.class).rootKey()).isEqualTo(new ThalesLunaVerifier().rootKey());
        assertThat(context.getBean(Crypto4AVerifier.class).rootKey()).isEqualTo(new Crypto4AVerifier().rootKey());
        assertThat(context.getBean(FortanixVerifier.class).root()).isEqualTo(new FortanixVerifier().root());
        assertThat(context.getBean(NShieldVerifier.class).rootKey().getEncoded())
                .isEqualTo(new NShieldVerifier().rootKey().getEncoded());

        assertThat(context.getBean(TrustAnchors.class).all())
                .allMatch(a -> a.origin().equals(TrustAnchors.ORIGIN_PINNED) && a.path() == null && a.matchesPinned());

        JsonNode fixture = TrustAnchorsTest.fixture("/fixtures/yubico/request.json");
        assertThat(context.getBean(YubicoVerifier.class).verifyYubicoAttestation(
                TrustAnchorsTest.texts(fixture.get("attestationCertChain")),
                TrustAnchorsTest.csrKey(fixture.get("csr").asText())).isValid()).isTrue();
    }
}
