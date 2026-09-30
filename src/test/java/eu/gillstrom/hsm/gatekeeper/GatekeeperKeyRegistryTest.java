package eu.gillstrom.hsm.gatekeeper;

import eu.gillstrom.hsm.testsupport.TestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class GatekeeperKeyRegistryTest {

    private KeyPair keyA;
    private KeyPair keyB;
    private X509Certificate certA;
    private X509Certificate certB;

    @BeforeEach
    void setUp() throws Exception {
        keyA = TestPki.newRsaKeyPair(2048);
        keyB = TestPki.newRsaKeyPair(2048);
        certA = TestPki.selfSignedCa(keyA, "Gatekeeper Signing A");
        certB = TestPki.selfSignedCa(keyB, "Gatekeeper Signing B");
    }

    @Test
    void newlineSeparatedCertificatesAreAllRegistered() throws Exception {
        String trustedKeys = TestPki.toPem(certA) + TestPki.toPem(certB);

        GatekeeperKeyRegistry registry = new GatekeeperKeyRegistry(trustedKeys);

        assertThat(registry.trustedFingerprints()).containsExactlyInAnyOrder(
                GatekeeperKeyRegistry.fingerprintHex(keyA.getPublic()),
                GatekeeperKeyRegistry.fingerprintHex(keyB.getPublic()));
    }

    @Test
    void commaSeparatedCertificatesAreAllRegistered() throws Exception {
        String trustedKeys = TestPki.toPem(certA).trim() + "," + TestPki.toPem(certB).trim();

        GatekeeperKeyRegistry registry = new GatekeeperKeyRegistry(trustedKeys);

        assertThat(registry.trustedFingerprints()).containsExactlyInAnyOrder(
                GatekeeperKeyRegistry.fingerprintHex(keyA.getPublic()),
                GatekeeperKeyRegistry.fingerprintHex(keyB.getPublic()));
    }
}
