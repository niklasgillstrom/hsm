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
 *   <li><b>BankID mandate</b> — {@code usrNonVisibleData} in the signed
 *       BankID payload must be a mandate ({@code hsm-mandate:v1}) for this
 *       organisation number and Swish number, and the visible text must state
 *       its count. The CSRs are created after the signature, one per call, so
 *       one mandate covers N requests with different CSRs.</li>
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

    /** A mandate text naming this request's organisation, Swish number and count, as BankIdConsentPolicy requires. */
    private static String mandateText(int count) {
        return "Testbolaget AB (556974-3098) ger harmed Teknisk leverantor AB fullmakt att hamta (" + count
                + ") Swish-certifikat for Swish-nummer 1231015932.";
    }
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
                new eu.gillstrom.hsm.verification.NShieldVerifier(),
                (pnr, org, swish) -> SignatoryRightsVerifier.Result.authorised("test"),
                null, null, null, TEST_KEY_POLICY, TEST_CONSENT_POLICY, CallerPolicy.off(), "SE");
    }

    @Test
    @DisplayName("A well-formed CSR under a BankID mandate is accepted")
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
    @DisplayName("One mandate covers several requests, each with its own CSR")
    void oneMandateCoversSeveralCsrs() throws Exception {
        String sig = mandate(ORG, SWISH, 2, mandateText(2));
        for (String name : new String[] {"A", "B"}) {
            KeyPair kp = TestPki.newRsaKeyPair(2048);
            String csrPem = TestPki.csrPem(kp, "Test Supplier " + name, kp.getPrivate());

            VerificationResponse r = service.verify(request(csrPem, sig));

            assertThat(r.isValid()).as("CSR %s: %s", name, r.getErrors()).isTrue();
        }
    }

    @Test
    @DisplayName("A mandate for another organisation or Swish number is rejected")
    void mandateForAnotherNumberIsRejected() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        String csrPem = TestPki.csrPem(kp, "Test Supplier", kp.getPrivate());
        for (String sig : new String[] {
                mandate("5569743099", SWISH, 1, mandateText(1)),
                mandate(ORG, "1231015933", 1, mandateText(1))}) {

            VerificationResponse r = service.verify(request(csrPem, sig));

            assertThat(r.isValid()).isFalse();
            assertThat(r.getErrors()).anyMatch(e -> e.startsWith("BANKID_NOT_BOUND_TO_REQUEST"));
        }
    }

    @Test
    @DisplayName("A BankID signature without a mandate is rejected")
    void bankIdSignatureWithoutBindingIsRejected() throws Exception {
        KeyPair subject = TestPki.newRsaKeyPair(2048);
        String csrPem = TestPki.csrPem(subject, "Test Supplier", subject.getPrivate());
        // Default fixture payload — a signature that authorises "something".
        String sig = fx.signedResponseBase64("Jag godkanner avtalet");

        VerificationResponse r = service.verify(request(csrPem, sig));

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("BANKID_NOT_BOUND_TO_REQUEST"));
    }

    @Test
    @DisplayName("The CSR-bound binding of 1.4.0-1.5.0 is no longer a mandate")
    void csrBoundBindingIsRejected() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        String csrPem = TestPki.csrPem(kp, "Test Supplier", kp.getPrivate());
        String v1 = "hsm-csr:v1;org=" + ORG + ";swish=" + SWISH + ";csr-sha256="
                + java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                        .digest(TestPki.csrDer(csrPem)));

        VerificationResponse r = service.verify(request(csrPem, fx.signedResponseBoundTo(mandateText(1), v1)));

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("BANKID_NOT_BOUND_TO_REQUEST"));
    }

    @Test
    @DisplayName("A count the signatory did not see is rejected")
    void countNotInTheVisibleTextIsRejected() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        String csrPem = TestPki.csrPem(kp, "Test Supplier", kp.getPrivate());
        // The signatory saw "(1)"; the non-visible mandate says 4.
        String sig = mandate(ORG, SWISH, 4, mandateText(1));

        VerificationResponse r = service.verify(request(csrPem, sig));

        assertThat(r.isValid()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("BANKID_VISIBLE_TEXT_MISMATCH")
                && e.contains("(4)"));
    }

    // ---------------------------------------------------------------- helpers

    /** A BankID signature carrying a one-certificate mandate for this organisation and Swish number. */
    private String bankIdSignedFor(String csrPem) throws Exception {
        return mandate(ORG, SWISH, 1, mandateText(1));
    }

    private String mandate(String org, String swish, int count, String visibleText) throws Exception {
        return fx.signedResponseBoundTo(visibleText, new BankIdService.Mandate(org, swish, count).canonical());
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
