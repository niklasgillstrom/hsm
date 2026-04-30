package eu.gillstrom.hsm.verification;

import org.junit.jupiter.api.Test;
import eu.gillstrom.hsm.testsupport.TestPki;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link YubicoVerifier}. A throwaway PKI can never be rooted at
 * the pinned Yubico YubiHSM root CA, so the expected outcome is always
 * chain-valid=false.
 */
class YubicoVerifierTest {

    @Test
    void chainNotRootedAtPinnedYubicoRootIsRejected() throws Exception {
        YubicoVerifier verifier = new YubicoVerifier();

        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate fakeRoot = TestPki.selfSignedCa(rootKp, "FAKE-YUBICO-ROOT");

        KeyPair deviceKp = TestPki.newRsaKeyPair(2048);
        X509Certificate deviceCert = TestPki.subordinateCa(
                deviceKp, "YubiHSM Attestation (FAKE1234)", fakeRoot, rootKp.getPrivate());

        KeyPair leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = TestPki.endEntity(
                leafKp, "FAKE-YUBI-ATTEST", deviceCert, deviceKp.getPrivate());

        List<String> chainPem = List.of(
                TestPki.toPem(attestCert),
                TestPki.toPem(deviceCert),
                TestPki.toPem(fakeRoot));

        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(chainPem, leafKp.getPublic());

        // PKIX against the pinned Yubico root must reject a fake chain.
        assertThat(r.isChainValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("chain"));

        // Public-key comparison still uses the leaf we submitted.
        assertThat(r.isPublicKeyMatch()).isTrue();

        // Overall verdict is false since chain is not valid.
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void emptyChainIsRejected() {
        YubicoVerifier verifier = new YubicoVerifier();
        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(java.util.Collections.emptyList(), null);

        assertThat(r.getErrors()).anyMatch(e -> e.toLowerCase().contains("no certificates"));
        assertThat(r.isValid()).isFalse();
    }
}
