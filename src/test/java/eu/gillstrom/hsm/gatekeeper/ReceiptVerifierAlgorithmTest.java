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
}
