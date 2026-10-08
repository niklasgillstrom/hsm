package eu.gillstrom.hsm.verification;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import eu.gillstrom.hsm.testsupport.TestPki;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
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
    void missingCapabilitiesExtensionIsRejected() throws Exception {
        YubicoVerifier verifier = new YubicoVerifier();

        // A certificate with no Yubico attestation extensions at all — in
        // particular no capabilities extension (1.3.6.1.4.1.41482.4.5). The
        // result's exportability flags default to false, which reads as "not
        // exportable"; an absent attribute must not be treated as a satisfied
        // attribute.
        KeyPair rootKp = TestPki.newRsaKeyPair(2048);
        X509Certificate fakeRoot = TestPki.selfSignedCa(rootKp, "FAKE-YUBICO-ROOT");
        KeyPair leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = TestPki.endEntity(
                leafKp, "FAKE-YUBI-ATTEST", fakeRoot, rootKp.getPrivate());

        YubicoVerifier.YubicoAttestationResult r = verifier.verifyYubicoAttestation(
                List.of(TestPki.toPem(attestCert), TestPki.toPem(fakeRoot)), leafKp.getPublic());

        assertThat(r.getErrors())
                .anyMatch(e -> e.contains("Capabilities attestation extension missing"));
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

    @Test
    void capabilitiesOfRealFixtureCarryNoExportFlags() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyCapabilities(bytes(0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x06, 0x60), r);

        assertThat(r.isExportableUnderWrap()).isFalse();
        assertThat(r.isCanExportWrapped()).isFalse();
        assertThat(r.isKeyExportable()).isFalse();
    }

    @Test
    void capabilitiesBit16IsExportableUnderWrap() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyCapabilities(bytes(0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00), r);

        assertThat(r.isExportableUnderWrap()).isTrue();
        assertThat(r.isCanExportWrapped()).isFalse();
    }

    @Test
    void capabilitiesBit12IsExportWrapped() {
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier.YubicoAttestationResult();
        YubicoVerifier.applyCapabilities(bytes(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00), r);

        assertThat(r.isCanExportWrapped()).isTrue();
        assertThat(r.isExportableUnderWrap()).isFalse();
    }

    @Test
    void exportableUnderWrapInAttestationCertificateIsRejected() throws Exception {
        YubicoVerifier verifier = new YubicoVerifier();
        KeyPair leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = attestationCert(leafKp,
                bytes(0x01), bytes(0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00));

        YubicoVerifier.YubicoAttestationResult r = verifier.verifyYubicoAttestation(
                List.of(TestPki.toPem(attestCert)), leafKp.getPublic());

        assertThat(r.isExportableUnderWrap()).isTrue();
        assertThat(r.getErrors()).anyMatch(e -> e.contains("export capabilities"));
        assertThat(r.isValid()).isFalse();
    }

    @Test
    void originGeneratedIsAccepted() throws Exception {
        YubicoVerifier verifier = new YubicoVerifier();
        KeyPair leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = attestationCert(leafKp,
                bytes(0x01), bytes(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

        YubicoVerifier.YubicoAttestationResult r = verifier.verifyYubicoAttestation(
                List.of(TestPki.toPem(attestCert)), leafKp.getPublic());

        assertThat(r.getKeyOrigin()).isEqualTo("generated");
        assertThat(r.getErrors()).noneMatch(e -> e.contains("origin"));
    }

    @Test
    void originGeneratedAndImportedWrappedIsRejected() throws Exception {
        YubicoVerifier verifier = new YubicoVerifier();
        KeyPair leafKp = TestPki.newRsaKeyPair(2048);
        X509Certificate attestCert = attestationCert(leafKp,
                bytes(0x11), bytes(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

        YubicoVerifier.YubicoAttestationResult r = verifier.verifyYubicoAttestation(
                List.of(TestPki.toPem(attestCert)), leafKp.getPublic());

        assertThat(r.isGenerated()).isTrue();
        assertThat(r.isImportedWrapped()).isTrue();
        assertThat(r.getKeyOrigin()).isEqualTo("imported_wrapped");
        assertThat(r.getErrors()).anyMatch(e -> e.contains("origin: imported_wrapped"));
        assertThat(r.isValid()).isFalse();
    }

    private static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }

    private static X509Certificate attestationCert(KeyPair subjectKp, byte[] origin, byte[] capabilities)
            throws Exception {
        KeyPair issuerKp = TestPki.newRsaKeyPair(2048);
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name("CN=FAKE-YUBICO-DEVICE"), BigInteger.valueOf(now),
                new Date(now - 60_000L), new Date(now + 3600_000L),
                new X500Name("CN=FAKE-YUBI-ATTEST"), subjectKp.getPublic());
        b.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.41482.4.3"), false, new DERBitString(origin));
        b.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.41482.4.5"), false, new DERBitString(capabilities));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }
}
