package eu.gillstrom.hsm.gatekeeper;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class HttpGatekeeperClientDeserializationTest {

    private static final String VERIFY_BODY = """
            {
              "verificationId": "test-uuid",
              "confirmationNonce": "test-nonce",
              "compliant": true,
              "verificationTimestamp": "2026-04-27T00:00:00Z",
              "signature": "c2lnbmF0dXJl",
              "signingCertificate": "-----BEGIN CERTIFICATE-----",
              "publicKeyFingerprint": "aa:bb",
              "publicKeyAlgorithm": "RSA",
              "hsmVendor": "YUBICO",
              "hsmModel": "YubiHSM 2",
              "hsmSerialNumber": "20783176",
              "keyProperties": {
                "generatedOnDevice": true,
                "exportable": true,
                "attestationChainValid": true,
                "publicKeyMatchesAttestation": true
              },
              "doraCompliance": {
                "article5_2b": true,
                "article6_10": true,
                "article9_3c": true,
                "article9_3d": true,
                "article9_4d": true,
                "article28_1a": true,
                "summary": "test"
              },
              "customerOrganisationNumber": "5569743098",
              "customerSwishNumber": "1231015932",
              "supplierIdentifier": "5566778899",
              "supplierNumber": "9871234567",
              "supplierName": "Test",
              "keyPurpose": "signing",
              "countryCode": "SE",
              "errors": [],
              "warnings": []
            }
            """;

    private static final String CONFIRM_BODY = """
            {
              "verificationId": "test-uuid",
              "loopClosed": true,
              "publicKeyMatch": true,
              "expectedPublicKeyFingerprint": "aa:bb",
              "actualPublicKeyFingerprint": "aa:bb",
              "registryStatus": "VERIFIED_AND_ISSUED",
              "processedTimestamp": "2026-04-27T00:00:01Z",
              "anomalies": []
            }
            """;

    private static final String NON_ISSUANCE_CONFIRM_BODY = """
            {
              "verificationId": "test-uuid",
              "loopClosed": true,
              "publicKeyMatch": null,
              "expectedPublicKeyFingerprint": "aa:bb",
              "actualPublicKeyFingerprint": null,
              "registryStatus": "VERIFIED_NOT_ISSUED",
              "processedTimestamp": "2026-04-27T00:00:01Z",
              "anomalies": []
            }
            """;

    private static final String EXPECTED_GOLDEN =
            "v3|test-uuid|test-nonce|true|2026-04-27T00:00:00Z|aa:bb|RSA|YUBICO|YubiHSM 2|"
            + "20783176|5569743098|1231015932|5566778899|9871234567|Test|signing|SE|"
            + "true|true|true|true|"
            + "true|true|true|true|true|true";

    @Test
    void verifyResponseDeserializesAndCanonicalizesToTheGoldenBytes() throws Exception {
        VerifyResponse r = HttpGatekeeperClient.MAPPER.readValue(VERIFY_BODY, VerifyResponse.class);

        assertThat(r.getVerificationId()).isEqualTo("test-uuid");
        assertThat(r.getConfirmationNonce()).isEqualTo("test-nonce");
        assertThat(r.isCompliant()).isTrue();
        assertThat(r.getVerificationTimestamp()).isEqualTo(Instant.parse("2026-04-27T00:00:00Z"));
        assertThat(r.getSignature()).isEqualTo("c2lnbmF0dXJl");
        assertThat(r.getKeyProperties().isGeneratedOnDevice()).isTrue();
        assertThat(r.getDoraCompliance().isArticle28_1a()).isTrue();
        assertThat(r.getDoraCompliance().getSummary()).isEqualTo("test");
        assertThat(r.getErrors()).isEmpty();

        assertThat(new String(ReceiptCanonicalizer.canonicalize(r), StandardCharsets.UTF_8))
                .isEqualTo(EXPECTED_GOLDEN);
    }

    @Test
    void issuanceConfirmResponseDeserializes() throws Exception {
        IssuanceConfirmResponse r =
                HttpGatekeeperClient.MAPPER.readValue(CONFIRM_BODY, IssuanceConfirmResponse.class);

        assertThat(r.getVerificationId()).isEqualTo("test-uuid");
        assertThat(r.isLoopClosed()).isTrue();
        assertThat(r.getPublicKeyMatch()).isTrue();
        assertThat(r.getActualPublicKeyFingerprint()).isEqualTo("aa:bb");
        assertThat(r.getRegistryStatus())
                .isEqualTo(IssuanceConfirmResponse.RegistryStatus.VERIFIED_AND_ISSUED);
        assertThat(r.getProcessedTimestamp()).isEqualTo("2026-04-27T00:00:01Z");
        assertThat(r.getAnomalies()).isEmpty();
    }

    @Test
    void nonIssuanceConfirmResponseDeserializes() throws Exception {
        IssuanceConfirmResponse r = HttpGatekeeperClient.MAPPER.readValue(
                NON_ISSUANCE_CONFIRM_BODY, IssuanceConfirmResponse.class);

        assertThat(r.getPublicKeyMatch()).isNull();
        assertThat(r.getActualPublicKeyFingerprint()).isNull();
        assertThat(r.getRegistryStatus())
                .isEqualTo(IssuanceConfirmResponse.RegistryStatus.VERIFIED_NOT_ISSUED);
    }
}
