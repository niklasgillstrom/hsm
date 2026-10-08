package eu.gillstrom.hsm.gatekeeper;

import eu.gillstrom.hsm.testsupport.TestPki;
import eu.gillstrom.hsm.util.Fingerprints;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The mock gatekeeper's receipts, confirmations and signing identity, and the
 * receipt verifier's refusals of a receipt or confirmation that is missing,
 * unsigned, or advertises an unparseable certificate or a non-base64
 * signature.
 */
class MockGatekeeperClientTest {

    private GatekeeperKeyRegistry registry;
    private MockGatekeeperClient mock;
    private ReceiptVerifier verifier;
    private KeyPair attested;

    @BeforeEach
    void setUp() throws Exception {
        registry = new GatekeeperKeyRegistry("");
        mock = new MockGatekeeperClient(registry);
        mock.init();
        verifier = new ReceiptVerifier(registry);
        attested = TestPki.newRsaKeyPair(2048);
    }

    private VerifyRequest request(String vendor) {
        return VerifyRequest.builder()
                .publicKey("-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getMimeEncoder().encodeToString(attested.getPublic().getEncoded())
                        + "\n-----END PUBLIC KEY-----")
                .hsmVendor(vendor).countryCode("SE").build();
    }

    private IssuanceConfirmRequest confirm(VerifyResponse receipt, boolean issued, String certificatePem) {
        return IssuanceConfirmRequest.builder()
                .verificationId(receipt.getVerificationId())
                .confirmationNonce(receipt.getConfirmationNonce())
                .issued(issued)
                .signingCertificatePem(certificatePem)
                .build();
    }

    @Test
    void theSigningIdentityIsA2048BitRsaCertificateValidNowAndForAYearAndRegistered() throws Exception {
        X509Certificate cert = mock.getSigningCertificate();

        cert.checkValidity();
        assertThat(cert.getNotBefore().toInstant()).isBefore(Instant.now());
        assertThat(cert.getNotAfter().toInstant()).isAfter(Instant.now().plus(Duration.ofDays(364)));
        assertThat(((RSAPublicKey) mock.getKeyPair().getPublic()).getModulus().bitLength()).isEqualTo(2048);
        assertThat(cert.getPublicKey()).isEqualTo(mock.getKeyPair().getPublic());
        assertThat(mock.getFingerprint())
                .isEqualTo(GatekeeperKeyRegistry.fingerprintHex(cert.getPublicKey()));
        assertThat(registry.findByFingerprint(mock.getFingerprint())).contains(cert);
    }

    @Test
    void aReceiptCarriesTheKeyFingerprintAFreshNonceAndTheVendorsModel() throws Exception {
        VerifyResponse yubico = mock.verify(request("YUBICO"));
        VerifyResponse securosys = mock.verify(request("securosys"));

        assertThat(yubico.getPublicKeyFingerprint()).isEqualTo(Fingerprints.ofPublicKey(attested.getPublic()));
        assertThat(yubico.getHsmModel()).isEqualTo("YubiHSM 2");
        assertThat(securosys.getHsmModel()).isEqualTo("Primus HSM");
        assertThat(mock.verify(request("AZURE")).getHsmModel()).isEqualTo("Azure Managed HSM");
        assertThat(mock.verify(request("GOOGLE")).getHsmModel()).isEqualTo("Google Cloud HSM");
        assertThat(mock.verify(request("THALES")).getHsmModel()).isEqualTo("Mock HSM");
        assertThat(mock.verify(request(null)).getHsmModel()).isEqualTo("Mock HSM");

        // 32 random bytes, base64url without padding.
        assertThat(yubico.getConfirmationNonce()).matches("[A-Za-z0-9_-]{43}");
        assertThat(yubico.getConfirmationNonce()).isNotEqualTo(securosys.getConfirmationNonce());
        assertThat(verifier.verify(yubico)).isTrue();
    }

    @Test
    void aRequestWithoutAPublicKeyGetsAReceiptWithoutAFingerprint() throws Exception {
        VerifyRequest noKey = VerifyRequest.builder().hsmVendor("YUBICO").countryCode("SE").build();
        VerifyRequest blankKey = VerifyRequest.builder().publicKey(" ").hsmVendor("YUBICO").countryCode("SE").build();

        assertThat(mock.verify(noKey).getPublicKeyFingerprint()).isNull();
        assertThat(mock.verify(blankKey).getPublicKeyFingerprint()).isNull();
    }

    @Test
    void aConfirmForAnUnknownVerificationIsASignedAnomaly() {
        IssuanceConfirmResponse response = mock.confirm(IssuanceConfirmRequest.builder()
                .verificationId("no-such-verification").confirmationNonce("x").issued(false).build());

        assertThat(response.isLoopClosed()).isFalse();
        assertThat(response.getRegistryStatus())
                .isEqualTo(IssuanceConfirmResponse.RegistryStatus.ANOMALY_UNKNOWN_VERIFICATION);
        assertThat(verifier.verifyConfirmation(response)).isTrue();
    }

    @Test
    void aConfirmWithoutIssuanceClosesTheLoopWithoutAKeyComparison() throws Exception {
        VerifyResponse receipt = mock.verify(request("YUBICO"));

        IssuanceConfirmResponse response = mock.confirm(confirm(receipt, false, null));

        assertThat(response.isLoopClosed()).isTrue();
        assertThat(response.getPublicKeyMatch()).isNull();
        assertThat(response.getRegistryStatus())
                .isEqualTo(IssuanceConfirmResponse.RegistryStatus.VERIFIED_NOT_ISSUED);
        assertThat(verifier.verifyConfirmation(response)).isTrue();
    }

    @Test
    void anIssuedCertificateIsComparedWithTheAttestedKey() throws Exception {
        String attestedPem = TestPki.toPem(TestPki.selfSignedCa(attested, "issued"));
        KeyPair other = TestPki.newRsaKeyPair(2048);
        String otherPem = TestPki.toPem(TestPki.selfSignedCa(other, "other"));

        IssuanceConfirmResponse match = mock.confirm(confirm(mock.verify(request("YUBICO")), true, attestedPem));
        IssuanceConfirmResponse mismatch = mock.confirm(confirm(mock.verify(request("YUBICO")), true, otherPem));

        assertThat(match.isLoopClosed()).isTrue();
        assertThat(match.getPublicKeyMatch()).isTrue();
        assertThat(match.getRegistryStatus())
                .isEqualTo(IssuanceConfirmResponse.RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(match.getAnomalies()).isEmpty();
        assertThat(mismatch.isLoopClosed()).isFalse();
        assertThat(mismatch.getPublicKeyMatch()).isFalse();
        assertThat(mismatch.getRegistryStatus())
                .isEqualTo(IssuanceConfirmResponse.RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
        assertThat(mismatch.getAnomalies())
                .containsExactly("public key in issued certificate does not match attested public key");
    }

    @Test
    void registeringReturnsTheKeyFingerprint() throws Exception {
        X509Certificate cert = TestPki.selfSignedCa(attested, "registered");
        String expected = GatekeeperKeyRegistry.fingerprintHex(attested.getPublic());

        assertThat(registry.register(cert)).isEqualTo(expected);
        assertThat(registry.registerFromPem(TestPki.toPem(cert))).isEqualTo(expected);
    }

    @Test
    void theVerifierRefusesWhatIsMissingUnsignedOrUnreadable() throws Exception {
        assertThat(verifier.verify(null)).isFalse();
        assertThat(verifier.verifyConfirmation(null)).isFalse();

        VerifyResponse unsigned = mock.verify(request("YUBICO"));
        unsigned.setSignature(" ");
        assertThat(verifier.verify(unsigned)).isFalse();

        VerifyResponse noCertificate = mock.verify(request("YUBICO"));
        noCertificate.setSigningCertificate(null);
        assertThat(verifier.verify(noCertificate)).isFalse();

        VerifyResponse badCertificate = mock.verify(request("YUBICO"));
        badCertificate.setSigningCertificate("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
        assertThat(verifier.verify(badCertificate)).isFalse();

        VerifyResponse badSignature = mock.verify(request("YUBICO"));
        badSignature.setSignature("not base64 !");
        assertThat(verifier.verify(badSignature)).isFalse();
    }

    @Test
    void aNullRequestIsRefused() {
        assertThatThrownBy(() -> mock.verify(null)).isInstanceOf(GatekeeperException.class);
        assertThatThrownBy(() -> mock.confirm(null)).isInstanceOf(GatekeeperException.class);
    }
}
