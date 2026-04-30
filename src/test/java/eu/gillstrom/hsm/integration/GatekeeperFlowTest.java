package eu.gillstrom.hsm.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import eu.gillstrom.hsm.gatekeeper.VerifyRequest;
import eu.gillstrom.hsm.gatekeeper.VerifyResponse;
import eu.gillstrom.hsm.gatekeeper.GatekeeperKeyRegistry;
import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmRequest;
import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmResponse;
import eu.gillstrom.hsm.gatekeeper.MockGatekeeperClient;
import eu.gillstrom.hsm.gatekeeper.ReceiptCanonicalizer;
import eu.gillstrom.hsm.gatekeeper.ReceiptVerifier;
import eu.gillstrom.hsm.issuance.IssuedCertificate;
import eu.gillstrom.hsm.issuance.MockIssuanceClient;
import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.model.VerificationResponse.CertificateType;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end exercise of the supervisory two-step gatekeeper protocol —
 * verify, then confirm — against the real Yubico production fixture in
 * {@code examples/yubico/}.
 *
 * <p>Three properties are tested:
 * <ol>
 *   <li>The mock gatekeeper signs a verify-step receipt that the local
 *       {@link ReceiptVerifier} accepts, and the subsequent confirm step
 *       reports {@code loopClosed=true} with {@code publicKeyMatch=true}.</li>
 *   <li>A receipt with a tampered signature is rejected by
 *       {@link ReceiptVerifier} — falsification harness for the trust
 *       boundary.</li>
 *   <li>{@link ReceiptCanonicalizer} produces a byte-identical canonical
 *       form to the gatekeeper's, asserted against a hardcoded expected
 *       byte sequence (the gatekeeper-side bytes are verified out-of-band).
 *       This guards against the protocol-level catastrophe of a one-character
 *       drift between the two implementations.</li>
 * </ol>
 */
class GatekeeperFlowTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path YUBICO_REQUEST = Paths.get("examples/yubico/request.json");

    private static GatekeeperKeyRegistry registry;
    private static MockGatekeeperClient gatekeeperClient;
    private static ReceiptVerifier receiptVerifier;
    private static MockIssuanceClient issuance;

    static boolean yubicoFixturePresent() {
        return Files.exists(YUBICO_REQUEST);
    }

    @BeforeAll
    static void setUp() throws Exception {
        registry = new GatekeeperKeyRegistry("");
        gatekeeperClient = new MockGatekeeperClient(registry);
        gatekeeperClient.init();
        receiptVerifier = new ReceiptVerifier(registry);
        issuance = new MockIssuanceClient();
        issuance.init();
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void mockFlowApprovesAndConfirms() throws Exception {
        CertificateRequest req = readFixtureAsRequest(YUBICO_REQUEST);
        VerifyRequest verifyRequest = buildVerifyRequest(req);

        // Phase 2: gatekeeper.verify
        VerifyResponse receipt = gatekeeperClient.verify(verifyRequest);
        assertThat(receipt.isCompliant()).isTrue();
        assertThat(receipt.getSignature()).isNotBlank();
        assertThat(receipt.getSigningCertificate()).contains("BEGIN CERTIFICATE");

        // Phase 2.5: locally verify the receipt's signature
        assertThat(receiptVerifier.verify(receipt))
                .as("mock-signed receipt must verify under the registered mock cert")
                .isTrue();

        // Phase 3: issuance — bound to the verifyId
        IssuedCertificate cert = issuance.issue(req, receipt.getVerificationId());
        assertThat(cert.certificatePem())
                .startsWith("-----BEGIN CERTIFICATE-----")
                .contains("-----END CERTIFICATE-----");
        assertThat(cert.verifyReceiptId()).isEqualTo(receipt.getVerificationId());

        // Phase 4: gatekeeper.confirm — must echo the nonce returned by verify
        IssuanceConfirmRequest confirmRequest = IssuanceConfirmRequest.builder()
                .verificationId(receipt.getVerificationId())
                .confirmationNonce(receipt.getConfirmationNonce())
                .issued(true)
                .signingCertificatePem(cert.certificatePem())
                .timestamp(DateTimeFormatter.ISO_INSTANT.format(Instant.now()))
                .swishNumber(req.getSwishNumber())
                .organisationNumber(req.getOrganisationNumber())
                .build();

        IssuanceConfirmResponse confirmResponse = gatekeeperClient.confirm(confirmRequest);
        // The mock approves the public key in the verify step against the CSR's
        // public key fingerprint. The mock issuance client issues a certificate
        // for the same CSR public key, so loopClosed and publicKeyMatch must both be true.
        assertThat(confirmResponse.isLoopClosed()).isTrue();
        assertThat(confirmResponse.getPublicKeyMatch()).isTrue();
        assertThat(confirmResponse.getRegistryStatus())
                .isEqualTo(IssuanceConfirmResponse.RegistryStatus.VERIFIED_AND_ISSUED);
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void receiptWithInvalidSignatureRejectsIssuance() throws Exception {
        CertificateRequest req = readFixtureAsRequest(YUBICO_REQUEST);
        VerifyRequest verifyRequest = buildVerifyRequest(req);

        VerifyResponse receipt = gatekeeperClient.verify(verifyRequest);

        // Tamper with the signature.
        byte[] tampered = Base64.getDecoder().decode(receipt.getSignature());
        tampered[0] ^= (byte) 0xFF;
        receipt.setSignature(Base64.getEncoder().encodeToString(tampered));

        assertThat(receiptVerifier.verify(receipt))
                .as("tampered signature must be rejected — the trust boundary protects "
                        + "the supervisory loop, not the entity's own optimism")
                .isFalse();
    }

    @Test
    void receiptCanonicalizerProducesByteIdenticalOutputToGatekeeper() {
        VerifyResponse fixed = VerifyResponse.builder()
                .verificationId("test-uuid")
                .compliant(true)
                .verificationTimestamp(Instant.parse("2026-04-27T00:00:00Z"))
                .publicKeyFingerprint("aa:bb")
                .publicKeyAlgorithm("RSA")
                .hsmVendor("YUBICO")
                .hsmModel("YubiHSM 2")
                .hsmSerialNumber("20783176")
                .supplierIdentifier("5569743098")
                .supplierName("Test")
                .keyPurpose("signing")
                .countryCode("SE")
                .keyProperties(VerifyResponse.KeyProperties.builder()
                        .generatedOnDevice(true)
                        .exportable(true)
                        .attestationChainValid(true)
                        .publicKeyMatchesAttestation(true)
                        .build())
                .doraCompliance(VerifyResponse.DoraCompliance.builder()
                        .article5_2b(true)
                        .article6_10(true)
                        .article9_3c(true)
                        .article9_3d(true)
                        .article9_4d(true)
                        .article28_1a(true)
                        .summary("test")
                        .build())
                .build();

        String expected = "v1|test-uuid|true|2026-04-27T00:00:00Z|aa:bb|RSA|YUBICO|YubiHSM 2|"
                + "20783176|5569743098|Test|signing|SE|true|true|true|true|true|true|true|true|true|true";
        byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
        byte[] actualBytes = ReceiptCanonicalizer.canonicalize(fixed);

        assertThat(actualBytes)
                .as("canonical bytes must be byte-identical to the gatekeeper's output; "
                        + "any drift breaks signature verification")
                .isEqualTo(expectedBytes);
    }

    // ---------------------------------------------------------------- helpers

    private static CertificateRequest readFixtureAsRequest(Path fixturePath) throws Exception {
        JsonNode n = MAPPER.readTree(Files.readString(fixturePath));
        CertificateRequest r = new CertificateRequest();
        r.setCsr(n.get("csr").asText());
        r.setHsmVendor(n.get("hsmVendor").asText());
        r.setCertificateType(CertificateType.SIGNING);
        r.setOrganisationNumber("5569743098");
        r.setSwishNumber("1231015932");
        List<String> chain = new ArrayList<>();
        for (JsonNode c : n.get("attestationCertChain")) {
            chain.add(c.asText());
        }
        r.setAttestationCertChain(chain);
        if (n.has("attestationData") && !n.get("attestationData").isNull()) {
            r.setAttestationData(n.get("attestationData").asText());
        }
        if (n.has("attestationSignature") && !n.get("attestationSignature").isNull()) {
            r.setAttestationSignature(n.get("attestationSignature").asText());
        }
        return r;
    }

    /**
     * Build the gatekeeper verify-request from a customer CertificateRequest,
     * using the same logic as AttestationService.buildVerifyRequest. We
     * extract the CSR's public key and PEM-encode it because the gatekeeper
     * wire format takes a raw public key, not a CSR.
     */
    private static VerifyRequest buildVerifyRequest(CertificateRequest req) throws Exception {
        String csrPem = req.getCsr().trim();
        if (!csrPem.contains("BEGIN")) {
            csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n" + req.getCsr()
                    + "\n-----END CERTIFICATE REQUEST-----";
        }
        try (var parser = new org.bouncycastle.openssl.PEMParser(new java.io.StringReader(csrPem))) {
            var csr = (org.bouncycastle.pkcs.PKCS10CertificationRequest) parser.readObject();
            var pk = new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest(csr).getPublicKey();
            String pkPem = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pk.getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";
            return VerifyRequest.builder()
                    .publicKey(pkPem)
                    .hsmVendor(req.getHsmVendor())
                    .attestationCertChain(req.getAttestationCertChain())
                    .attestationData(req.getAttestationData())
                    .attestationSignature(req.getAttestationSignature())
                    .supplierIdentifier(req.getOrganisationNumber())
                    .keyPurpose("Swish SIGNING")
                    .countryCode("SE")
                    .build();
        }
    }
}
