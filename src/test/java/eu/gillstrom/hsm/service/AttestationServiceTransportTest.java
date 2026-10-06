package eu.gillstrom.hsm.service;

import eu.gillstrom.hsm.issuance.MockIssuanceClient;
import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.model.IssuanceResponse;
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
 * TRANSPORT certificates carry no HSM-attestation requirement, but they are
 * still issued in the organisation's name: the BankID signatory must be
 * confirmed as authorised for the organisation, exactly as for SIGNING. And
 * because no gatekeeper takes part, the outcome must not be reported as a
 * supervised, confirmed issuance.
 */
class AttestationServiceTransportTest {

    private static final String ORG = "5569743098";
    private static final String SWISH = "1231015932";

    /** The synthetic keys in this test are RSA-2048; the key policy is tested in KeyPolicyTest. */
    private static final KeyPolicy TEST_KEY_POLICY =
            new KeyPolicy("RSA-2048", KeyPolicy.DEFAULT_ALLOWED_CSR_SIGNATURE_ALGORITHMS);

    private BankIdFixture fx;
    private MockIssuanceClient issuance;

    @BeforeEach
    void setUp() throws Exception {
        fx = new BankIdFixture();
        issuance = new MockIssuanceClient();
        issuance.init();
    }

    @Test
    @DisplayName("TRANSPORT without confirmed signatory rights is rejected")
    void transportWithoutConfirmedSignatoryRightsIsRejected() throws Exception {
        AttestationService service = service(new FailClosedSignatoryRightsVerifier());

        VerificationResponse r = service.verify(boundTransportRequest());

        assertThat(r.isValid()).isFalse();
        assertThat(r.isAuthorizedSignatory()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("Signatory rights not confirmed"));
    }

    @Test
    @DisplayName("TRANSPORT without confirmed signatory rights is not issued")
    void transportWithoutConfirmedSignatoryRightsIsNotIssued() throws Exception {
        AttestationService service = service(new FailClosedSignatoryRightsVerifier());

        IssuanceResponse r = service.verifyAndIssue(boundTransportRequest());

        assertThat(r.isIssued()).isFalse();
        assertThat(r.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_LOCAL_VERIFICATION);
    }

    @Test
    @DisplayName("An authorised TRANSPORT issuance is not reported as supervised")
    void authorisedTransportIsIssuedAsNotSupervised() throws Exception {
        AttestationService service = service(
                (pnr, org, swish) -> SignatoryRightsVerifier.Result.authorised("test"));

        IssuanceResponse r = service.verifyAndIssue(boundTransportRequest());

        assertThat(r.isIssued()).isTrue();
        assertThat(r.getStage().name()).isEqualTo("ISSUED_TRANSPORT_NOT_SUPERVISED");
        assertThat(r.getVerifyReceipt()).isNull();
        assertThat(r.getConfirmResponse()).isNull();
    }

    @Test
    @DisplayName("The default key policy refuses an RSA-2048 TRANSPORT request")
    void defaultKeyPolicyRefusesRsa2048() throws Exception {
        AttestationService service = new AttestationService(
                new BankIdService(fx.anchors()), new SecurosysVerifier(), new YubicoVerifier(),
                new AzureHsmVerifier(), new GoogleCloudHsmVerifier(),
                (pnr, org, swish) -> SignatoryRightsVerifier.Result.authorised("test"),
                null, null, issuance, KeyPolicy.defaults(), "SE");

        IssuanceResponse r = service.verifyAndIssue(boundTransportRequest());

        assertThat(r.isIssued()).isFalse();
        assertThat(r.getErrors()).anyMatch(e -> e.startsWith("KEY_POLICY_VIOLATION"));
    }

    // ---------------------------------------------------------------- helpers

    private AttestationService service(SignatoryRightsVerifier signatoryRights) {
        return new AttestationService(
                new BankIdService(fx.anchors()),
                new SecurosysVerifier(),
                new YubicoVerifier(),
                new AzureHsmVerifier(),
                new GoogleCloudHsmVerifier(),
                signatoryRights,
                null, null, issuance, TEST_KEY_POLICY, "SE");
    }

    private CertificateRequest boundTransportRequest() throws Exception {
        KeyPair subject = TestPki.newRsaKeyPair(2048);
        String csrPem = TestPki.csrPem(subject, "Test Supplier", subject.getPrivate());
        String binding = BankIdService.expectedBinding(ORG, SWISH, TestPki.csrDer(csrPem));
        String signature = fx.signedResponseBoundTo("Jag godkanner avtalet", binding);

        CertificateRequest r = new CertificateRequest();
        r.setCsr(csrPem);
        r.setCertificateType(CertificateType.TRANSPORT);
        r.setOrganisationNumber(ORG);
        r.setSwishNumber(SWISH);
        r.setBankIdSignatureResponse(signature);
        r.setBankIdOcspResponse(fx.ocspResponseBase64(signature));
        return r;
    }
}
