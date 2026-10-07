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

    /** A mandate text naming this request's organisation, Swish number and count, as BankIdConsentPolicy requires. */
    private static String mandateText(int count) {
        return "Testbolaget AB (556974-3098) ger harmed Teknisk leverantor AB fullmakt att hamta (" + count
                + ") Swish-certifikat for Swish-nummer 1231015932.";
    }
    /** The fixture's BankID relying party (srvInfo serialNumber). */
    private static final BankIdConsentPolicy TEST_CONSENT_POLICY = new BankIdConsentPolicy("5566778899");

    private BankIdFixture fx;
    private GatekeeperKeyRegistry registry;
    private RecordingGatekeeperClient gatekeeper;
    private MockGatekeeperClient mock;
    private MockIssuanceClient issuance;

    static boolean yubicoFixturePresent() {
        return Files.exists(YUBICO_REQUEST);
    }

    @BeforeEach
    void setUp() throws Exception {
        fx = new BankIdFixture();
        registry = new GatekeeperKeyRegistry("");
        mock = new MockGatekeeperClient(registry);
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
    void unsignedConfirmIsNotAClosedLoop() throws Exception {
        // Whoever can answer the confirm call returns a well-formed
        // loopClosed=true envelope without the gatekeeper's signature.
        gatekeeper.confirmOverride = req -> IssuanceConfirmResponse.builder()
                .verificationId(req.getVerificationId())
                .loopClosed(true)
                .publicKeyMatch(true)
                .actualPublicKeyFingerprint(gatekeeper.lastVerifiedFingerprint)
                .registryStatus(IssuanceConfirmResponse.RegistryStatus.VERIFIED_AND_ISSUED)
                .build();

        IssuanceResponse r = service("SE").verifyAndIssue(signingRequest());

        assertThat(r.getStage()).isEqualTo(IssuanceResponse.Stage.ISSUED_BUT_CONFIRM_NOT_CLOSED);
        assertThat(r.getErrors()).anyMatch(e -> e.contains("signature did not verify"));
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void signedConfirmForAnotherKeyIsNotAClosedLoop() throws Exception {
        // A genuinely signed confirm that names a different public key than
        // the CSR carries does not close this request's loop.
        gatekeeper.confirmOverride = req -> {
            IssuanceConfirmResponse c = mock.confirm(req);
            c.setActualPublicKeyFingerprint("00:11:22");
            resign(c);
            return c;
        };

        IssuanceResponse r = service("SE").verifyAndIssue(signingRequest());

        assertThat(r.getStage()).isEqualTo(IssuanceResponse.Stage.ISSUED_BUT_CONFIRM_NOT_CLOSED);
        assertThat(r.getErrors()).anyMatch(e -> e.contains("but this request carries"));
    }

    /** A genuinely signed receipt whose fields are changed before it is signed. */
    private void tamperedReceipt(java.util.function.Consumer<VerifyResponse> change) {
        gatekeeper.verifyOverride = r -> {
            change.accept(r);
            try {
                java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
                sig.initSign(mock.getKeyPair().getPrivate());
                sig.update(eu.gillstrom.hsm.gatekeeper.ReceiptCanonicalizer.canonicalize(r));
                r.setSignature(java.util.Base64.getEncoder().encodeToString(sig.sign()));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
            return r;
        };
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void receiptFieldsMustMatchTheRequest() throws Exception {
        java.util.Map<String, java.util.function.Consumer<VerifyResponse>> cases = new java.util.LinkedHashMap<>();
        cases.put("countryCode", r -> r.setCountryCode("NO"));
        cases.put("supplierIdentifier", r -> r.setSupplierIdentifier("5560000000"));
        cases.put("keyPurpose", r -> r.setKeyPurpose("Swish TRANSPORT"));
        cases.put("hsmVendor", r -> r.setHsmVendor("SECUROSYS"));
        cases.put("verificationTimestamp", r -> r.setVerificationTimestamp(java.time.Instant.now().minusSeconds(6 * 60)));
        cases.put("verificationTimestamp in the future", r -> r.setVerificationTimestamp(java.time.Instant.now().plusSeconds(6 * 60)));
        cases.put("no verificationTimestamp", r -> r.setVerificationTimestamp(null));
        cases.put("keyProperties", r -> r.setKeyProperties(null));
        cases.put("exportable", r -> r.getKeyProperties().setExportable(true));
        cases.put("generatedOnDevice", r -> r.getKeyProperties().setGeneratedOnDevice(false));
        cases.put("attestationChainValid", r -> r.getKeyProperties().setAttestationChainValid(false));
        cases.put("publicKeyMatchesAttestation", r -> r.getKeyProperties().setPublicKeyMatchesAttestation(false));
        for (var c : cases.entrySet()) {
            tamperedReceipt(c.getValue());
            IssuanceResponse r = service("SE").verifyAndIssue(signingRequest());
            assertThat(r.getStage()).as(c.getKey()).isEqualTo(IssuanceResponse.Stage.REJECTED_RECEIPT_MISMATCH);
            assertThat(r.isIssued()).as(c.getKey()).isFalse();
            assertThat(r.getErrors()).as(c.getKey()).singleElement().asString().startsWith("RECEIPT_MISMATCH");
        }
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void receiptWithinTheLimitsIsAccepted() throws Exception {
        java.util.List<java.util.function.Consumer<VerifyResponse>> cases = java.util.List.of(
                r -> r.setVerificationTimestamp(java.time.Instant.now().minusSeconds(4 * 60)),
                r -> r.setVerificationTimestamp(java.time.Instant.now().plusSeconds(4 * 60)),
                r -> r.setHsmVendor("Yubico"),
                r -> r.setCountryCode("se"));
        for (var c : cases) {
            tamperedReceipt(c);
            assertThat(service("SE").verifyAndIssue(signingRequest()).getStage())
                    .isEqualTo(IssuanceResponse.Stage.VERIFIED_ISSUED_AND_CONFIRMED);
        }
    }

    private void resign(IssuanceConfirmResponse c) {
        try {
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
            sig.initSign(mock.getKeyPair().getPrivate());
            sig.update(eu.gillstrom.hsm.gatekeeper.ConfirmationCanonicalizer.canonicalize(c));
            c.setSignature(java.util.Base64.getEncoder().encodeToString(sig.sign()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void aOneCertificateMandateAuthorisesOneSigningIssuance() throws Exception {
        AttestationService service = service("SE");
        CertificateRequest request = signingRequest();
        assertThat(service.verifyAndIssue(request).getStage())
                .isEqualTo(IssuanceResponse.Stage.VERIFIED_ISSUED_AND_CONFIRMED);

        IssuanceResponse again = service.verifyAndIssue(request);

        assertThat(again.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_BANKID_ALREADY_USED);
        assertThat(again.isIssued()).isFalse();
        assertThat(gatekeeper.lastConfirm.isIssued())
                .as("the second gatekeeper verification is closed as not issued").isFalse();
        assertThat(gatekeeper.lastConfirm.getVerificationId())
                .isEqualTo(again.getVerifyReceipt().getVerificationId());
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
                new eu.gillstrom.hsm.verification.MarvellHsmVerifier(),
                new eu.gillstrom.hsm.verification.ThalesLunaVerifier(),
                new eu.gillstrom.hsm.verification.Crypto4AVerifier(),
                new eu.gillstrom.hsm.verification.FortanixVerifier(),
                new eu.gillstrom.hsm.verification.NShieldVerifier(),
                (personalNumber, organisationNumber, swishNumber) ->
                        SignatoryRightsVerifier.Result.authorised("test"),
                gatekeeper,
                new ReceiptVerifier(registry),
                issuance,
                KeyPolicy.defaults(),
                TEST_CONSENT_POLICY,
                CallerPolicy.off(),
                countryCode);
    }

    private CertificateRequest signingRequest() throws Exception {
        JsonNode n = MAPPER.readTree(Files.readString(YUBICO_REQUEST));
        String csrPem = n.get("csr").asText();
        List<String> chain = new ArrayList<>();
        for (JsonNode c : n.get("attestationCertChain")) {
            chain.add(c.asText());
        }
        String signature = fx.signedResponseBoundTo(mandateText(1),
                new BankIdService.Mandate(ORG, SWISH, 1).canonical());

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
        private String lastVerifiedFingerprint;
        private java.util.function.Function<IssuanceConfirmRequest, IssuanceConfirmResponse> confirmOverride;
        private java.util.function.UnaryOperator<VerifyResponse> verifyOverride;

        RecordingGatekeeperClient(GatekeeperClient delegate) {
            this.delegate = delegate;
        }

        @Override
        public VerifyResponse verify(VerifyRequest request) {
            lastVerify = request;
            VerifyResponse r = delegate.verify(request);
            lastVerifiedFingerprint = r.getPublicKeyFingerprint();
            return verifyOverride != null ? verifyOverride.apply(r) : r;
        }

        @Override
        public IssuanceConfirmResponse confirm(IssuanceConfirmRequest request) {
            lastConfirm = request;
            return confirmOverride != null ? confirmOverride.apply(request) : delegate.confirm(request);
        }
    }
}
