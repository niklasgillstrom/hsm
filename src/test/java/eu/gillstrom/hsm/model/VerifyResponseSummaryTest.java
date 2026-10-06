package eu.gillstrom.hsm.model;

import eu.gillstrom.hsm.gatekeeper.GatekeeperKeyRegistry;
import eu.gillstrom.hsm.gatekeeper.ReceiptCanonicalizer;
import eu.gillstrom.hsm.gatekeeper.ReceiptVerifier;
import eu.gillstrom.hsm.gatekeeper.VerifyResponse;
import eu.gillstrom.hsm.testsupport.TestPki;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The receipt summary in {@link IssuanceResponse} is the audit record an
 * auditor works from. It must carry every field the gatekeeper signed, in a
 * form that rebuilds the exact canonical bytes, or the retained signature
 * can no longer be verified.
 */
class VerifyResponseSummaryTest {

    @Test
    @DisplayName("A receipt with key properties and DORA mapping re-verifies from the summary")
    void fullReceiptReverifies() throws Exception {
        Signed s = signed(VerifyResponse.builder()
                .keyProperties(new VerifyResponse.KeyProperties(true, false, true, true))
                .doraCompliance(new VerifyResponse.DoraCompliance(true, true, true, true, true, true, "ok")));

        assertThat(s.verifier.verify(IssuanceResponse.VerifyResponseSummary.from(s.receipt).toVerifyResponse()))
                .isTrue();
    }

    @Test
    @DisplayName("A receipt without key properties or DORA mapping re-verifies from the summary")
    void receiptWithoutSubObjectsReverifies() throws Exception {
        Signed s = signed(VerifyResponse.builder());

        assertThat(s.verifier.verify(IssuanceResponse.VerifyResponseSummary.from(s.receipt).toVerifyResponse()))
                .isTrue();
    }

    private record Signed(VerifyResponse receipt, ReceiptVerifier verifier) {
    }

    private static Signed signed(VerifyResponse.VerifyResponseBuilder b) throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        X509Certificate cert = TestPki.selfSignedCa(kp, "Gatekeeper Signing Test");
        GatekeeperKeyRegistry registry = new GatekeeperKeyRegistry("");
        registry.register(cert);

        VerifyResponse receipt = b
                .verificationId("v-1")
                .confirmationNonce("n-1")
                .compliant(true)
                .verificationTimestamp(Instant.parse("2026-10-06T00:00:00Z"))
                .publicKeyFingerprint("aa:bb")
                .publicKeyAlgorithm("RSA")
                .hsmVendor("YUBICO")
                .hsmModel("YubiHSM 2")
                .hsmSerialNumber("1")
                .supplierIdentifier("5569743098")
                .supplierName("Test")
                .keyPurpose("Swish SIGNING")
                .countryCode("SE")
                .errors(List.of())
                .warnings(List.of())
                .signingCertificate(TestPki.toPem(cert))
                .build();
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());
        sig.update(ReceiptCanonicalizer.canonicalize(receipt));
        receipt.setSignature(Base64.getEncoder().encodeToString(sig.sign()));
        return new Signed(receipt, new ReceiptVerifier(registry));
    }
}
