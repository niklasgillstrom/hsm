package eu.gillstrom.hsm.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gillstrom.hsm.gatekeeper.GatekeeperClient;
import eu.gillstrom.hsm.gatekeeper.GatekeeperKeyRegistry;
import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmRequest;
import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmResponse;
import eu.gillstrom.hsm.gatekeeper.MockGatekeeperClient;
import eu.gillstrom.hsm.gatekeeper.ReceiptVerifier;
import eu.gillstrom.hsm.gatekeeper.VerifyRequest;
import eu.gillstrom.hsm.gatekeeper.VerifyResponse;
import eu.gillstrom.hsm.issuance.MockIssuanceClient;
import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.model.IssuanceResponse;
import eu.gillstrom.hsm.model.VerificationResponse.CertificateType;
import eu.gillstrom.hsm.testsupport.BankIdFixture;
import eu.gillstrom.hsm.testsupport.TestPki;
import eu.gillstrom.hsm.util.Fingerprints;
import eu.gillstrom.hsm.verification.AzureHsmVerifier;
import eu.gillstrom.hsm.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.hsm.verification.SecurosysVerifier;
import eu.gillstrom.hsm.verification.YubicoVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AttestationServiceGatekeeperFlowTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path YUBICO_REQUEST = Paths.get("examples/yubico/request.json");
    private static final String ORG = "5569743098";
    private static final String SWISH = "1231015932";

    private BankIdFixture fx;
    private GatekeeperKeyRegistry registry;
    private RecordingGatekeeperClient gatekeeper;
    private MockIssuanceClient issuance;

    static boolean yubicoFixturePresent() {
        return Files.exists(YUBICO_REQUEST);
    }

    @BeforeEach
    void setUp() throws Exception {
        fx = new BankIdFixture();
        registry = new GatekeeperKeyRegistry("");
        MockGatekeeperClient mock = new MockGatekeeperClient(registry);
        mock.init();
        gatekeeper = new RecordingGatekeeperClient(mock);
        issuance = new MockIssuanceClient();
        issuance.init();
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void confirmCarriesTheIssuedCertificatePem() throws Exception {
        IssuanceResponse r = service("SE").verifyAndIssue(signingRequest());

        assertThat(r.getStage()).as("errors: %s", r.getErrors())
                .isEqualTo(IssuanceResponse.Stage.VERIFIED_ISSUED_AND_CONFIRMED);

        IssuanceConfirmRequest confirm = gatekeeper.lastConfirm;
        assertThat(confirm).isNotNull();
        assertThat(confirm.isIssued()).isTrue();
        assertThat(confirm.getSigningCertificatePem())
                .isNotBlank()
                .isEqualTo(r.getCertificate().getCertificatePem());

        X509Certificate sent = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(
                        confirm.getSigningCertificatePem().getBytes(StandardCharsets.UTF_8)));
        assertThat(sent.getIssuerX500Principal().getName()).isEqualTo(r.getCertificate().getIssuerDn());
        assertThat(Fingerprints.ofPublicKey(sent.getPublicKey()))
                .isEqualTo(r.getVerification().getCsrPublicKeyFingerprint());
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void retainedReceiptReverifiesFromTheAuditRecord() throws Exception {
        IssuanceResponse r = service("SE").verifyAndIssue(signingRequest());

        assertThat(r.getStage()).as("errors: %s", r.getErrors())
                .isEqualTo(IssuanceResponse.Stage.VERIFIED_ISSUED_AND_CONFIRMED);
        VerifyResponse rebuilt = r.getVerifyReceipt().toVerifyResponse();
        assertThat(new ReceiptVerifier(registry).verify(rebuilt))
                .as("the audit record must carry every signed receipt field")
                .isTrue();
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void verifyRequestCarriesTheConfiguredCountryCode() throws Exception {
        IssuanceResponse r = service("NO").verifyAndIssue(signingRequest());

        assertThat(r.getStage()).as("errors: %s", r.getErrors())
                .isEqualTo(IssuanceResponse.Stage.VERIFIED_ISSUED_AND_CONFIRMED);
        assertThat(gatekeeper.lastVerify).isNotNull();
        assertThat(gatekeeper.lastVerify.getCountryCode()).isEqualTo("NO");
    }

    private AttestationService service(String countryCode) {
        return new AttestationService(
                new BankIdService(fx.anchors()),
                new SecurosysVerifier(),
                new YubicoVerifier(),
                new AzureHsmVerifier(),
                new GoogleCloudHsmVerifier(),
                (personalNumber, organisationNumber, swishNumber) ->
                        SignatoryRightsVerifier.Result.authorised("test"),
                gatekeeper,
                new ReceiptVerifier(registry),
                issuance,
                KeyPolicy.defaults(),
                countryCode);
    }

    private CertificateRequest signingRequest() throws Exception {
        JsonNode n = MAPPER.readTree(Files.readString(YUBICO_REQUEST));
        String csrPem = n.get("csr").asText();
        List<String> chain = new ArrayList<>();
        for (JsonNode c : n.get("attestationCertChain")) {
            chain.add(c.asText());
        }
        String binding = BankIdService.expectedBinding(ORG, SWISH, TestPki.csrDer(csrPem));
        String signature = fx.signedResponseBoundTo("Jag godkanner avtalet", binding);

        CertificateRequest r = new CertificateRequest();
        r.setCsr(csrPem);
        r.setCertificateType(CertificateType.SIGNING);
        r.setHsmVendor(n.get("hsmVendor").asText());
        r.setAttestationCertChain(chain);
        r.setOrganisationNumber(ORG);
        r.setSwishNumber(SWISH);
        r.setBankIdSignatureResponse(signature);
        r.setBankIdOcspResponse(fx.ocspResponseBase64(signature));
        return r;
    }

    private static final class RecordingGatekeeperClient implements GatekeeperClient {

        private final GatekeeperClient delegate;
        private VerifyRequest lastVerify;
        private IssuanceConfirmRequest lastConfirm;

        RecordingGatekeeperClient(GatekeeperClient delegate) {
            this.delegate = delegate;
        }

        @Override
        public VerifyResponse verify(VerifyRequest request) {
            lastVerify = request;
            return delegate.verify(request);
        }

        @Override
        public IssuanceConfirmResponse confirm(IssuanceConfirmRequest request) {
            lastConfirm = request;
            return delegate.confirm(request);
        }
    }
}
