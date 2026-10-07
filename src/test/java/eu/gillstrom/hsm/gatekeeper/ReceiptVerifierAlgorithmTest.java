package eu.gillstrom.hsm.gatekeeper;

import eu.gillstrom.hsm.testsupport.TestPki;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * gatekeeper signs receipts with {@code gatekeeper.signing.algorithm}
 * (SHA256withRSA by default, or for example SHA384withRSA or
 * SHA256withECDSA); hsm verifies with the algorithm configured to match.
 */
class ReceiptVerifierAlgorithmTest {

    private static VerifyResponse receipt(KeyPair kp, X509Certificate cert, String algorithm) throws Exception {
        VerifyResponse r = VerifyResponse.builder()
                .verificationId("VID-1")
                .confirmationNonce("n")
                .compliant(true)
                .verificationTimestamp(Instant.parse("2026-10-06T12:00:00Z"))
                .publicKeyFingerprint("ab")
                .signingCertificate(TestPki.toPem(cert))
                .build();
        Signature s = Signature.getInstance(algorithm);
        s.initSign(kp.getPrivate());
        s.update(ReceiptCanonicalizer.canonicalize(r));
        r.setSignature(Base64.getEncoder().encodeToString(s.sign()));
        return r;
    }

    private static X509Certificate ecCert(KeyPair kp) throws Exception {
        X500Name name = new X500Name("CN=EC gatekeeper");
        return new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(name,
                BigInteger.ONE, new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis()
                + 3_600_000), name, kp.getPublic()).build(new JcaContentSignerBuilder("SHA256withECDSA")
                .build(kp.getPrivate())));
    }

    @Test
    void aReceiptSignedByAKeyOutsideTheRegistryIsRefused() throws Exception {
        // The receipt is correctly signed and advertises the certificate of
        // the key that signed it, but that key is not a registered gatekeeper
        // key: anyone can mint such a receipt.
        KeyPair registered = TestPki.newRsaKeyPair(2048);
        X509Certificate registeredCert = TestPki.selfSignedCa(registered, "Registered gatekeeper");
        KeyPair forger = TestPki.newRsaKeyPair(2048);
        X509Certificate forgerCert = TestPki.selfSignedCa(forger, "Registered gatekeeper");
        ReceiptVerifier verifier = new ReceiptVerifier(new GatekeeperKeyRegistry(TestPki.toPem(registeredCert)));

        assertThat(verifier.verify(receipt(registered, registeredCert, "SHA256withRSA"))).isTrue();
        assertThat(verifier.verify(receipt(forger, forgerCert, "SHA256withRSA"))).isFalse();
    }

    @Test
    void theDefaultIsSha256WithRsa() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = TestPki.selfSignedCa(kp, "RSA gatekeeper");
        GatekeeperKeyRegistry registry = new GatekeeperKeyRegistry(TestPki.toPem(cert));

        assertThat(new ReceiptVerifier(registry).verify(receipt(kp, cert, "SHA256withRSA"))).isTrue();
        assertThat(new ReceiptVerifier(registry).verify(receipt(kp, cert, "SHA384withRSA"))).isFalse();
    }

    @Test
    void theConfiguredAlgorithmIsUsed() throws Exception {
        KeyPair rsa = TestPki.newRsaKeyPair(2048);
        X509Certificate rsaCert = TestPki.selfSignedCa(rsa, "RSA gatekeeper");
        ReceiptVerifier sha384 = new ReceiptVerifier(new GatekeeperKeyRegistry(TestPki.toPem(rsaCert)), "SHA384withRSA");
        assertThat(sha384.verify(receipt(rsa, rsaCert, "SHA384withRSA"))).isTrue();
        assertThat(sha384.verify(receipt(rsa, rsaCert, "SHA256withRSA"))).isFalse();

        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ec = g.generateKeyPair();
        X509Certificate ecCert = ecCert(ec);
        ReceiptVerifier ecdsa = new ReceiptVerifier(new GatekeeperKeyRegistry(TestPki.toPem(ecCert)), "SHA256withECDSA");
        assertThat(ecdsa.verify(receipt(ec, ecCert, "SHA256withECDSA"))).isTrue();
        assertThat(new ReceiptVerifier(new GatekeeperKeyRegistry(TestPki.toPem(ecCert)))
                .verify(receipt(ec, ecCert, "SHA256withECDSA"))).isFalse();
    }

    @Test
    void anUnknownAlgorithmIsAStartUpFailure() {
        assertThatThrownBy(() -> new ReceiptVerifier(new GatekeeperKeyRegistry(""), "SHA256withNothing"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new ReceiptVerifier(new GatekeeperKeyRegistry(""), "SHA1withRSA"))
                .isInstanceOf(IllegalStateException.class);
    }

    /** The 1.5.0 golden literal, for a receipt without the 1.6.0 party fields. */
    private static final String V2_GOLDEN = "v2|VID-1|n|true|2026-10-06T12:00:00Z|ab|||||||||"
            + "|||||||||";

    private static VerifyResponse v2Signed(KeyPair kp, X509Certificate cert) throws Exception {
        VerifyResponse r = VerifyResponse.builder()
                .verificationId("VID-1")
                .confirmationNonce("n")
                .compliant(true)
                .verificationTimestamp(Instant.parse("2026-10-06T12:00:00Z"))
                .publicKeyFingerprint("ab")
                .signingCertificate(TestPki.toPem(cert))
                .build();
        byte[] v2 = ReceiptCanonicalizer.canonicalize(r, ReceiptCanonicalizer.PREVIOUS_VERSION);
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(kp.getPrivate());
        s.update(v2);
        r.setSignature(Base64.getEncoder().encodeToString(s.sign()));
        return r;
    }

    @Test
    void aReceiptSignedBefore160StaysVerifiable() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = TestPki.selfSignedCa(kp, "RSA gatekeeper");
        ReceiptVerifier verifier = new ReceiptVerifier(new GatekeeperKeyRegistry(TestPki.toPem(cert)));
        VerifyResponse old = v2Signed(kp, cert);

        assertThat(new String(ReceiptCanonicalizer.canonicalize(old, "v2"), java.nio.charset.StandardCharsets.UTF_8))
                .as("the v2 form is the one 1.5.0 signed: no customer fields, no supplier number")
                .isEqualTo(V2_GOLDEN);
        assertThat(verifier.verify(old)).isTrue();
    }

    @Test
    void partyFieldsCannotBeAddedToAReceiptSignedBefore160() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = TestPki.selfSignedCa(kp, "RSA gatekeeper");
        ReceiptVerifier verifier = new ReceiptVerifier(new GatekeeperKeyRegistry(TestPki.toPem(cert)));
        for (java.util.function.Consumer<VerifyResponse> add : java.util.List.<java.util.function.Consumer<VerifyResponse>>of(
                r -> r.setCustomerOrganisationNumber("5569743098"),
                r -> r.setCustomerSwishNumber("1231015932"),
                r -> r.setSupplierNumber("9871234567"))) {
            VerifyResponse old = v2Signed(kp, cert);
            add.accept(old);
            assertThat(verifier.verify(old)).isFalse();
        }
        // A v3 receipt is not accepted as v2 either: its signature covers more.
        VerifyResponse v3 = receipt(kp, cert, "SHA256withRSA");
        assertThat(verifier.verify(v3)).isTrue();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> ReceiptCanonicalizer.canonicalize(v3, "v1"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
