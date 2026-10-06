package eu.gillstrom.hsm.service;

import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.model.VerificationResponse;
import eu.gillstrom.hsm.model.VerificationResponse.CertificateType;
import eu.gillstrom.hsm.testsupport.BankIdFixture;
import eu.gillstrom.hsm.testsupport.TestPki;
import eu.gillstrom.hsm.verification.AzureHsmVerifier;
import eu.gillstrom.hsm.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.hsm.verification.SecurosysVerifier;
import eu.gillstrom.hsm.verification.YubicoVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers the two request-level bindings introduced in v1.4.0:
 *
 * <ol>
 *   <li><b>CSR proof of possession</b> — the CSR's own signature must verify
 *       under the public key the CSR carries, so a requester cannot submit a
 *       public key whose private half belongs to somebody else.</li>
 *   <li><b>BankID request binding</b> — {@code usrNonVisibleData} in the signed
 *       BankID payload must equal the canonical binding string for this
 *       organisation number, Swish number and CSR, so a signature legitimately
 *       collected for one request cannot be presented with another CSR.</li>
 * </ol>
 *
 * <p>TRANSPORT requests are used because they exercise the same two checks
 * without requiring HSM attestation evidence. Signatory rights are confirmed
 * by a stub so that only the two bindings decide the outcome; the signatory
 * check itself is covered in {@link AttestationServiceTransportTest}. All
 * material is synthetic.</p>
 */
class AttestationServiceRequestBindingTest {

    private static final String ORG = "5569743098";
    private static final String SWISH = "1231015932";

    /** The synthetic keys in this test are RSA-2048; the key policy is tested in KeyPolicyTest. */
    private static final KeyPolicy TEST_KEY_POLICY =
            new KeyPolicy("RSA-2048", KeyPolicy.DEFAULT_ALLOWED_CSR_SIGNATURE_ALGORITHMS);

    /** A mandate text naming this request's organisation and Swish number, as BankIdConsentPolicy requires. */
    private static final String MANDATE =
            "Testbolaget AB (556974-3098) ger harmed Teknisk leverantor AB fullmakt att hamta "
            + "Swish-certifikat for Swish-nummer 1231015932.";
    /** The fixture's BankID relying party (srvInfo serialNumber). */
    private static final BankIdConsentPolicy TEST_CONSENT_POLICY = new BankIdConsentPolicy("5566778899");

    private BankIdFixture fx;
    private AttestationService service;

    @BeforeEach
    void setUp() throws Exception {
        fx = new BankIdFixture();
        service = new AttestationService(
                new BankIdService(fx.anchors()),
                new SecurosysVerifier(),
                new YubicoVerifier(),
                new AzureHsmVerifier(),
                new GoogleCloudHsmVerifier(),
                new eu.gillstrom.hsm.verification.MarvellHsmVerifier(),
                new eu.gillstrom.hsm.verification.ThalesLunaVerifier(),
                new eu.gillstrom.hsm.verification.Crypto4AVerifier(),
                new eu.gillstrom.hsm.verification.FortanixVerifier(),
                (pnr, org, swish) -> SignatoryRightsVerifier.Result.authorised("test"),
                null, null, null, TEST_KEY_POLICY, TEST_CONSENT_POLICY, "SE");
    }

    @Test
    @DisplayName("A well-formed CSR bound to the BankID signature is accepted")
    void boundRequestIsAccepted() throws Exception {
        KeyPair subject = TestPki.newRsaKeyPair(2048);
        String csrPem = TestPki.csrPem(subject, "Test Supplier", subject.getPrivate());

        VerificationResponse r = service.verify(request(csrPem, bankIdSignedFor(csrPem)));

        assertThat(r.getErrors()).isEmpty();
        assertThat(r.isValid()).as("errors: %s", r.getErrors()).isTrue();
    }

    @Test
    @DisplayName("A CSR signed by a key other than the one it carries is rejected")
    void csrWithoutProofOfPossessionIsRejected() throws Exception {
        KeyPair subject = TestPki.newRsaKeyPair(2048);
        KeyPair impostor = TestPki.newRsaKeyPair(2048);
        // Well-formed PKCS#10, parses cleanly, carries `subject`'s public key —
        // but is signed with a private key that does not belong to it.
        String csrPem = TestPki.csrPem(subject, "Test Supplier", impostor.getPrivate());

        VerificationResponse r = service.verify(request(csrPem, bankIdSignedFor(csrPem)));

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("CSR_SIGNATURE_INVALID"));
    }

    @Test
    @DisplayName("A BankID signature bound to another CSR is rejected")
    void bankIdSignatureForAnotherCsrIsRejected() throws Exception {
        KeyPair a = TestPki.newRsaKeyPair(2048);
        KeyPair b = TestPki.newRsaKeyPair(2048);
        String csrA = TestPki.csrPem(a, "Test Supplier A", a.getPrivate());
        String csrB = TestPki.csrPem(b, "Test Supplier B", b.getPrivate());

        // A genuine BankID signature — collected for CSR A, presented with B.
        VerificationResponse r = service.verify(request(csrB, bankIdSignedFor(csrA)));

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("BANKID_NOT_BOUND_TO_REQUEST"));
    }

    @Test
    @DisplayName("A BankID signature without the binding payload is rejected")
    void bankIdSignatureWithoutBindingIsRejected() throws Exception {
        KeyPair subject = TestPki.newRsaKeyPair(2048);
        String csrPem = TestPki.csrPem(subject, "Test Supplier", subject.getPrivate());
        // Default fixture payload — a signature that authorises "something".
        String sig = fx.signedResponseBase64("Jag godkanner avtalet");

        VerificationResponse r = service.verify(request(csrPem, sig));

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("BANKID_NOT_BOUND_TO_REQUEST"));
    }

    // ---------------------------------------------------------------- helpers

    /** A BankID signature whose usrNonVisibleData binds it to the given CSR. */
    private String bankIdSignedFor(String csrPem) throws Exception {
        String binding = BankIdService.expectedBinding(ORG, SWISH, TestPki.csrDer(csrPem));
        return fx.signedResponseBoundTo(MANDATE, binding);
    }

    private CertificateRequest request(String csrPem, String bankIdSignature) throws Exception {
        CertificateRequest r = new CertificateRequest();
        r.setCsr(csrPem);
        r.setCertificateType(CertificateType.TRANSPORT);
        r.setOrganisationNumber(ORG);
        r.setSwishNumber(SWISH);
        r.setBankIdSignatureResponse(bankIdSignature);
        r.setBankIdOcspResponse(fx.ocspResponseBase64(bankIdSignature));
        return r;
    }
}
