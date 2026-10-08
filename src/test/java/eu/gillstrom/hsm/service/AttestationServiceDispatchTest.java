package eu.gillstrom.hsm.service;

import eu.gillstrom.hsm.gatekeeper.GatekeeperClient;
import eu.gillstrom.hsm.gatekeeper.GatekeeperException;
import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmRequest;
import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmResponse;
import eu.gillstrom.hsm.gatekeeper.ReceiptVerifier;
import eu.gillstrom.hsm.gatekeeper.VerifyRequest;
import eu.gillstrom.hsm.gatekeeper.VerifyResponse;
import eu.gillstrom.hsm.issuance.IssuanceClient;
import eu.gillstrom.hsm.issuance.IssuanceException;
import eu.gillstrom.hsm.issuance.IssuedCertificate;
import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.model.VerificationResponse.CertificateType;
import eu.gillstrom.hsm.model.HsmVendor;
import eu.gillstrom.hsm.model.IssuanceResponse;
import eu.gillstrom.hsm.model.VerificationResponse;
import eu.gillstrom.hsm.testsupport.TestPki;
import eu.gillstrom.hsm.util.Fingerprints;
import eu.gillstrom.hsm.verification.AzureHsmVerifier;
import eu.gillstrom.hsm.verification.Crypto4AVerifier;
import eu.gillstrom.hsm.verification.FortanixVerifier;
import eu.gillstrom.hsm.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.hsm.verification.MarvellHsmVerifier;
import eu.gillstrom.hsm.verification.NShieldVerifier;
import eu.gillstrom.hsm.verification.SecurosysVerifier;
import eu.gillstrom.hsm.verification.ThalesLunaVerifier;
import eu.gillstrom.hsm.verification.YubicoVerifier;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * How {@link AttestationService} turns the BankID result, each vendor
 * verifier's result and the gatekeeper's answers into a verification and an
 * issuance outcome. Everything it calls is a mock: what is tested here is the
 * dispatch, the required inputs per vendor, the early refusals and every
 * stage of the issuance flow, not the parsing behind them.
 */
class AttestationServiceDispatchTest {

    private static final String ORG = "5569743098";
    private static final String SWISH = "1231015932";
    private static final String PNR = "190001019999";

    private static KeyPair kp;
    private static String csrPem;
    private static String csrFingerprint;

    private final BankIdService bankId = mock(BankIdService.class);
    private final SecurosysVerifier securosys = mock(SecurosysVerifier.class);
    private final YubicoVerifier yubico = mock(YubicoVerifier.class);
    private final AzureHsmVerifier azure = mock(AzureHsmVerifier.class);
    private final GoogleCloudHsmVerifier google = mock(GoogleCloudHsmVerifier.class);
    private final MarvellHsmVerifier marvell = mock(MarvellHsmVerifier.class);
    private final ThalesLunaVerifier thales = mock(ThalesLunaVerifier.class);
    private final Crypto4AVerifier crypto4a = mock(Crypto4AVerifier.class);
    private final FortanixVerifier fortanix = mock(FortanixVerifier.class);
    private final NShieldVerifier nshield = mock(NShieldVerifier.class);
    private final GatekeeperClient gatekeeper = mock(GatekeeperClient.class);
    private final ReceiptVerifier receiptVerifier = mock(ReceiptVerifier.class);
    private final IssuanceClient issuance = mock(IssuanceClient.class);
    private SignatoryRightsVerifier.Result signatory = SignatoryRightsVerifier.Result.authorised("test");
    private AttestationService service;

    @BeforeAll
    static void keys() throws Exception {
        kp = TestPki.newRsaKeyPair(2048);
        csrPem = TestPki.csrPem(kp, "Test", kp.getPrivate());
        csrFingerprint = Fingerprints.ofPublicKey(kp.getPublic());
    }

    @BeforeEach
    void setUp() {
        BankIdService.BankIdResult bankIdResult = new BankIdService.BankIdResult();
        bankIdResult.setValid(true);
        bankIdResult.setSignatureValid(true);
        bankIdResult.setCertificateChainValid(true);
        bankIdResult.setPersonalNumber(PNR);
        bankIdResult.setUsrNonVisibleData(new BankIdService.Mandate(ORG, SWISH, 1).canonical());
        bankIdResult.setSignatureTime(Instant.now());
        when(bankId.verify(any(), any())).thenReturn(bankIdResult);
        when(bankId.consume(any(), any(), anyInt())).thenReturn(true);
        when(receiptVerifier.verify(any())).thenReturn(true);
        when(receiptVerifier.verifyConfirmation(any())).thenReturn(true);
        service = new AttestationService(bankId, securosys, yubico, azure, google, marvell, thales, crypto4a,
                fortanix, nshield, (p, o, s) -> signatory, gatekeeper, receiptVerifier, issuance,
                mock(KeyPolicy.class), mock(BankIdConsentPolicy.class), CallerPolicy.off(), "SE");
    }

    private static CertificateRequest request(String vendor, String data, List<String> chain) {
        CertificateRequest r = new CertificateRequest();
        r.setCsr(csrPem);
        r.setCertificateType(CertificateType.SIGNING);
        r.setHsmVendor(vendor);
        r.setAttestationData(data);
        r.setAttestationSignature("sig");
        r.setAttestationCertChain(chain);
        r.setOrganisationNumber(ORG);
        r.setSwishNumber(SWISH);
        r.setBankIdSignatureResponse("signature");
        r.setBankIdOcspResponse("ocsp");
        return r;
    }

    private static CertificateRequest request(String vendor) {
        return request(vendor, "data", List.of("chain"));
    }

    // ---- vendor results ---------------------------------------------------------------------

    /** What a verifier reports, in the terms every result class shares. */
    private record Outcome(boolean valid, boolean match, boolean chain, boolean exportable, String serial,
                           List<String> errors) {
        static Outcome good() {
            return new Outcome(true, true, true, false, "SER", List.of());
        }

        static Outcome refused() {
            return new Outcome(false, false, false, true, "SER", List.of("REFUSED"));
        }
    }

    private void stub(String vendor, Outcome o) {
        switch (vendor) {
            case "SECUROSYS" -> {
                var r = mock(SecurosysVerifier.SecurosysAttestationResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.getHsmSerialNumber()).thenReturn(o.serial());
                when(r.getKeyOrigin()).thenReturn("generated");
                when(r.isExtractable()).thenReturn(o.exportable());
                when(securosys.verifySecurosysAttestation(any(), any(), any(), any())).thenReturn(r);
            }
            case "YUBICO" -> {
                var r = mock(YubicoVerifier.YubicoAttestationResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.getKeyOrigin()).thenReturn("generated");
                when(r.isKeyExportable()).thenReturn(o.exportable());
                when(r.getDeviceSerial()).thenReturn(o.serial());
                when(yubico.verifyYubicoAttestation(any(), any())).thenReturn(r);
            }
            case "AZURE" -> {
                var r = mock(AzureHsmVerifier.AzureAttestationResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.getKeyOrigin()).thenReturn("generated");
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getHsmPool()).thenReturn(o.serial());
                when(azure.verifyAzureAttestation(any(), any())).thenReturn(r);
            }
            case "GOOGLE" -> {
                var r = mock(GoogleCloudHsmVerifier.GoogleAttestationResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.getKeyOrigin()).thenReturn("generated");
                when(r.isExtractable()).thenReturn(o.exportable());
                when(r.getKeyId()).thenReturn(o.serial());
                when(google.verifyGoogleAttestation(any(), any(), any())).thenReturn(r);
            }
            case "MARVELL" -> {
                var r = mock(MarvellHsmVerifier.MarvellAttestationResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.getKeyOrigin()).thenReturn("generated");
                when(r.isExtractable()).thenReturn(o.exportable());
                when(r.getPartitionSerial()).thenReturn(o.serial());
                when(marvell.verifyMarvellAttestation(any(), any(), any())).thenReturn(r);
            }
            case "THALES" -> {
                var r = mock(ThalesLunaVerifier.ThalesLunaResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.getKeyOrigin()).thenReturn("generated");
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getHsmSerial()).thenReturn(o.serial());
                when(thales.verifyLunaAttestation(any(), any())).thenReturn(r);
            }
            case "CRYPTO4A" -> {
                var r = mock(Crypto4AVerifier.Crypto4AResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.getKeyOrigin()).thenReturn("generated");
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getHsmSerial()).thenReturn(o.serial());
                when(crypto4a.verifyCrypto4AAttestation(any(), any())).thenReturn(r);
            }
            case "FORTANIX" -> {
                var r = mock(FortanixVerifier.FortanixResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.getKeyOrigin()).thenReturn("generated");
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getKeyId()).thenReturn(o.serial());
                when(fortanix.verifyFortanixAttestation(any(), any())).thenReturn(r);
            }
            case "ENTRUST" -> {
                var r = mock(NShieldVerifier.NShieldResult.class);
                when(r.isValid()).thenReturn(o.valid());
                when(r.getErrors()).thenReturn(o.errors());
                when(r.isPublicKeyMatch()).thenReturn(o.match());
                when(r.isChainValid()).thenReturn(o.chain());
                when(r.getKeyOrigin()).thenReturn("generated");
                when(r.isExportable()).thenReturn(o.exportable());
                when(r.getEsn()).thenReturn(o.serial());
                when(nshield.verifyNShieldAttestation(any(), any())).thenReturn(r);
            }
            default -> throw new IllegalArgumentException(vendor);
        }
    }

    private static final List<String[]> VENDORS = List.of(
            new String[] {"SECUROSYS", "Primus HSM"},
            new String[] {"YUBICO", "YubiHSM 2"},
            new String[] {"AZURE", "Azure Managed HSM"},
            new String[] {"GOOGLE", "Google Cloud HSM"},
            new String[] {"MARVELL", "Marvell LiquidSecurity"},
            new String[] {"THALES", "Thales Luna"},
            new String[] {"CRYPTO4A", "Crypto4A QASM"},
            new String[] {"FORTANIX", "Fortanix DSM"},
            new String[] {"ENTRUST", "Entrust nShield"});

    @Test
    void eachVendorsCleanResultIsReportedAndAccepted() {
        for (String[] v : VENDORS) {
            stub(v[0], Outcome.good());
            VerificationResponse r = service.verify(request(v[0]));

            assertThat(r.getErrors()).as(v[0]).isEmpty();
            assertThat(r.isValid()).as(v[0]).isTrue();
            assertThat(r.getHsmVendor()).as(v[0]).isEqualTo(HsmVendor.valueOf(v[0]).getVendorName());
            assertThat(r.getHsmModel()).as(v[0]).isEqualTo(v[1]);
            assertThat(r.getHsmSerialNumber()).as(v[0]).isEqualTo("SER");
            assertThat(r.getKeyOrigin()).as(v[0]).isEqualTo("generated");
            assertThat(r.isKeyExportable()).as(v[0]).isFalse();
            assertThat(r.isPublicKeyMatch()).as(v[0]).isTrue();
            assertThat(r.isAttestationChainValid()).as(v[0]).isTrue();
            assertThat(r.getAttestedPublicKeyFingerprint()).as(v[0]).isEqualTo(csrFingerprint);
            assertThat(r.getCsrPublicKeyFingerprint()).as(v[0]).isEqualTo(csrFingerprint);
        }
    }

    @Test
    void eachVendorsRefusalIsReportedAndRefused() {
        for (String[] v : VENDORS) {
            stub(v[0], Outcome.refused());
            VerificationResponse r = service.verify(request(v[0]));

            assertThat(r.getErrors()).as(v[0]).containsExactly("REFUSED");
            assertThat(r.isValid()).as(v[0]).isFalse();
            assertThat(r.isKeyExportable()).as(v[0]).isTrue();
            assertThat(r.getAttestedPublicKeyFingerprint()).as(v[0]).isNull();
        }
    }

    @Test
    void aValidResultWithoutAKeyMatchOrChainIsStillRefused() {
        stub("YUBICO", new Outcome(true, false, true, false, "SER", List.of()));
        assertThat(service.verify(request("YUBICO")).isValid()).isFalse();
        stub("YUBICO", new Outcome(true, true, false, false, "SER", List.of()));
        assertThat(service.verify(request("YUBICO")).isValid()).isFalse();
    }

    @Test
    void securosysAndGoogleNameTheKeyInTheModelWhenTheyKnowItsSize() {
        var s = mock(SecurosysVerifier.SecurosysAttestationResult.class);
        when(s.isValid()).thenReturn(true);
        when(s.isPublicKeyMatch()).thenReturn(true);
        when(s.isChainValid()).thenReturn(true);
        when(s.getKeySize()).thenReturn("4096");
        when(s.getAlgorithm()).thenReturn("RSA");
        when(securosys.verifySecurosysAttestation(any(), any(), any(), any())).thenReturn(s);
        VerificationResponse sr = service.verify(request("SECUROSYS"));
        assertThat(sr.getHsmModel()).isEqualTo("Primus HSM (RSA 4096)");
        assertThat(sr.getKeyOrigin()).isEqualTo("unverified");

        for (int size : new int[] {0, 1}) {
            var g = mock(GoogleCloudHsmVerifier.GoogleAttestationResult.class);
            when(g.getKeySize()).thenReturn(size);
            when(g.getKeyType()).thenReturn("RSA");
            when(google.verifyGoogleAttestation(any(), any(), any())).thenReturn(g);
            assertThat(service.verify(request("GOOGLE")).getHsmModel())
                    .isEqualTo(size == 0 ? "Google Cloud HSM" : "Google Cloud HSM (RSA 1)");
        }
    }

    @Test
    void eachVendorsRequiredEvidenceIsNamedWhenMissing() {
        String[][] dataRequired = {
                {"AZURE", "attestationData (JSON from az keyvault key get-attestation) is required for Azure"},
                {"GOOGLE", "attestationData (base64 of attestation.dat) is required for Google Cloud HSM"},
                {"MARVELL", "attestationData (base64 of attest.dat) is required for Marvell LiquidSecurity"},
                {"THALES", "attestationData (base64 of the PKC from cmu getpkc) is required for Thales Luna"},
                {"CRYPTO4A", "attestationData (the QASM attestation message, base64 or PEM) is required for Crypto4A"},
                {"FORTANIX", "attestationData (the DSM key attestation JSON) is required for Fortanix"},
                {"ENTRUST", "attestationData (the nShield key attestation bundle JSON) is required for Entrust"}};
        for (String[] v : dataRequired) {
            for (String data : new String[] {null, " "}) {
                VerificationResponse r = service.verify(request(v[0], data, List.of("chain")));
                assertThat(r.getErrors()).as(v[0] + " " + data).containsExactly(v[1]);
                assertThat(r.isValid()).isFalse();
            }
        }

        assertThat(service.verify(request("SECUROSYS", null, List.of("c"))).getErrors())
                .containsExactly("attestationData (XML) is required for Securosys");
        CertificateRequest noSignature = request("SECUROSYS");
        noSignature.setAttestationSignature(null);
        assertThat(service.verify(noSignature).getErrors())
                .containsExactly("attestationSignature is required for Securosys");
        for (List<String> chain : new ArrayList<List<String>>(java.util.Arrays.asList(null, List.of()))) {
            assertThat(service.verify(request("SECUROSYS", "data", chain)).getErrors())
                    .containsExactly("attestationCertChain is required for Securosys");
            assertThat(service.verify(request("YUBICO", "data", chain)).getErrors())
                    .containsExactly("attestationCertChain is required for Yubico");
        }
    }

    @Test
    void anUnknownOrMissingVendorIsRefused() {
        for (String vendor : new String[] {null, " ", "acme"}) {
            assertThat(service.verify(request(vendor)).getErrors()).as(vendor)
                    .containsExactly("hsmVendor is required for signing certificates");
        }
        stub("YUBICO", Outcome.good());
        assertThat(service.verify(request("yubico")).isValid()).isTrue();
    }

    // ---- refusals before any vendor is asked -----------------------------------------------

    @Test
    void theCertificateTypeMustBeGivenAndMatchTheEvidence() {
        CertificateRequest noType = request("YUBICO");
        noType.setCertificateType(null);
        VerificationResponse r = service.verify(noType);
        assertThat(r.isValid()).isFalse();
        assertThat(r.getCertificateType()).isEqualTo(CertificateType.TRANSPORT);
        assertThat(r.getErrors()).containsExactly("certificateType is required (SIGNING or TRANSPORT)");

        CertificateRequest signingWithout = request("YUBICO", null, null);
        assertThat(service.verify(signingWithout).getErrors()).singleElement().asString()
                .startsWith("SIGNING requests require HSM attestation evidence");

        CertificateRequest transportWith = request("YUBICO");
        transportWith.setCertificateType(CertificateType.TRANSPORT);
        assertThat(service.verify(transportWith).getErrors()).singleElement().asString()
                .startsWith("TRANSPORT requests must not carry HSM attestation data");
    }

    @Test
    void anUnreadableCsrOrOneWhoseKeyCannotCheckItsSignatureIsRefused() throws Exception {
        CertificateRequest garbage = request("YUBICO");
        garbage.setCsr("not a csr");
        assertThat(service.verify(garbage).getErrors()).singleElement().asString().startsWith("Invalid CSR: ");

        // A CSR whose SubjectPublicKeyInfo names an algorithm no provider knows:
        // its proof of possession cannot be checked, which is a failed check.
        SubjectPublicKeyInfo unknown = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4")), new byte[] {1, 2, 3});
        byte[] der = new PKCS10CertificationRequestBuilder(new X500Name("CN=x"), unknown)
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())).getEncoded();
        CertificateRequest unknownKey = request("YUBICO");
        unknownKey.setCsr("-----BEGIN CERTIFICATE REQUEST-----\n"
                + Base64.getMimeEncoder().encodeToString(der) + "\n-----END CERTIFICATE REQUEST-----\n");
        assertThat(service.verify(unknownKey).getErrors()).singleElement().asString()
                .startsWith("CSR_SIGNATURE_INVALID");
    }

    @Test
    void anUnconfirmedSignatoryIsNamedWithTheReasonOrItsAbsence() {
        stub("YUBICO", Outcome.good());
        signatory = SignatoryRightsVerifier.Result.unauthorised("not in the register");
        assertThat(service.verify(request("YUBICO")).getErrors())
                .containsExactly("Signatory rights not confirmed (status=UNAUTHORISED): not in the register");

        signatory = new SignatoryRightsVerifier.Result(SignatoryRightsVerifier.Result.Status.UNKNOWN, null, null);
        assertThat(service.verify(request("YUBICO")).getErrors())
                .containsExactly("Signatory rights not confirmed (status=UNKNOWN): no reason given");
    }

    @Test
    void aTwelveDigitPersonalNumberIsMaskedAndAnythingShorterIsNot() {
        stub("YUBICO", Outcome.good());
        assertThat(service.verify(request("YUBICO")).getBankIdPersonalNumber()).isEqualTo("19000101****");

        for (String pnr : new String[] {"19000101999", null}) {
            BankIdService.BankIdResult b = new BankIdService.BankIdResult();
            b.setValid(true);
            b.setPersonalNumber(pnr);
            when(bankId.verify(any(), any())).thenReturn(b);
            assertThat(service.verify(request("YUBICO")).getBankIdPersonalNumber()).isEqualTo(pnr);
        }
    }

    // ---- the issuance flow -----------------------------------------------------------------

    private static VerifyResponse receipt() {
        return VerifyResponse.builder()
                .verificationId("v-1")
                .confirmationNonce("nonce")
                .compliant(true)
                .verificationTimestamp(Instant.now())
                .publicKeyFingerprint(csrFingerprint)
                .hsmVendor("YUBICO")
                .keyProperties(VerifyResponse.KeyProperties.builder().generatedOnDevice(true).exportable(false)
                        .attestationChainValid(true).publicKeyMatchesAttestation(true).build())
                .customerOrganisationNumber(ORG)
                .customerSwishNumber(SWISH)
                .keyPurpose("Swish SIGNING")
                .countryCode("SE")
                .errors(List.of())
                .build();
    }

    private static IssuedCertificate certificate() {
        return new IssuedCertificate("-----BEGIN CERTIFICATE-----", "CN=CA", "CN=leaf",
                Instant.now(), Instant.now(), "iss-1", "v-1");
    }

    private static IssuanceConfirmResponse closed() {
        return IssuanceConfirmResponse.builder()
                .verificationId("v-1")
                .loopClosed(true)
                .publicKeyMatch(true)
                .actualPublicKeyFingerprint(csrFingerprint)
                .registryStatus(IssuanceConfirmResponse.RegistryStatus.VERIFIED_AND_ISSUED)
                .anomalies(List.of())
                .build();
    }

    private IssuanceResponse issue(VerifyResponse receipt) {
        stub("YUBICO", Outcome.good());
        when(gatekeeper.verify(any())).thenReturn(receipt);
        when(issuance.issue(any(), any())).thenReturn(certificate());
        return service.verifyAndIssue(request("YUBICO"));
    }

    @Test
    void aClosedLoopIsIssuedAndConfirmedAndTheGatekeeperIsToldWhatWasRequested() {
        when(gatekeeper.confirm(any())).thenReturn(closed());
        IssuanceResponse r = issue(receipt());

        assertThat(r.getStage()).as("%s", r.getErrors()).isEqualTo(IssuanceResponse.Stage.VERIFIED_ISSUED_AND_CONFIRMED);
        assertThat(r.getConfirmResponse().getVerificationId()).isEqualTo("v-1");
        assertThat(r.getConfirmResponse().getRegistryStatus())
                .isEqualTo(IssuanceConfirmResponse.RegistryStatus.VERIFIED_AND_ISSUED);
        ArgumentCaptor<VerifyRequest> sent = ArgumentCaptor.forClass(VerifyRequest.class);
        verify(gatekeeper).verify(sent.capture());
        assertThat(sent.getValue().getKeyPurpose()).isEqualTo("Swish SIGNING");
        assertThat(sent.getValue().getCountryCode()).isEqualTo("SE");
    }

    @Test
    void aGatekeeperThatCannotBeReachedRefusesTheIssuance() {
        stub("YUBICO", Outcome.good());
        when(gatekeeper.verify(any())).thenThrow(new GatekeeperException("down"));

        IssuanceResponse r = service.verifyAndIssue(request("YUBICO"));

        assertThat(r.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_GATEKEEPER_VERIFY_FAILED);
        assertThat(r.getErrors()).containsExactly("down");
        verify(issuance, never()).issue(any(), any());
    }

    @Test
    void noReceiptOrANonCompliantOneRefusesTheIssuance() {
        IssuanceResponse none = issue(null);
        assertThat(none.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_GATEKEEPER_NOT_COMPLIANT);
        assertThat(none.getErrors()).containsExactly("gatekeeper returned compliant=false");
        assertThat(none.getVerifyReceipt()).isNull();

        VerifyResponse refused = receipt();
        refused.setCompliant(false);
        refused.setErrors(List.of("NOT_GENERATED"));
        IssuanceResponse withReason = issue(refused);
        assertThat(withReason.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_GATEKEEPER_NOT_COMPLIANT);
        assertThat(withReason.getErrors()).containsExactly("NOT_GENERATED");
        assertThat(withReason.getVerifyReceipt().getVerificationId()).isEqualTo("v-1");

        refused.setErrors(null);
        assertThat(issue(refused).getErrors()).containsExactly("gatekeeper returned compliant=false");
        verify(issuance, never()).issue(any(), any());
    }

    @Test
    void anUnverifiableReceiptOrOneForAnotherKeyRefusesTheIssuance() {
        when(receiptVerifier.verify(any())).thenReturn(false);
        IssuanceResponse unverified = issue(receipt());
        assertThat(unverified.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_GATEKEEPER_RECEIPT_INVALID);
        assertThat(unverified.getVerifyReceipt().getVerificationId()).isEqualTo("v-1");

        when(receiptVerifier.verify(any())).thenReturn(true);
        VerifyResponse other = receipt();
        other.setPublicKeyFingerprint("00:11");
        IssuanceResponse mismatch = issue(other);
        assertThat(mismatch.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_RECEIPT_KEY_MISMATCH);
        assertThat(mismatch.getErrors()).containsExactly("RECEIPT_KEY_MISMATCH: the gatekeeper receipt approves "
                + "public key 00:11 but this request carries " + csrFingerprint);
        verify(issuance, never()).issue(any(), any());
    }

    @Test
    void aFailedIssuanceIsReportedToTheGatekeeperAsNotIssued() {
        stub("YUBICO", Outcome.good());
        when(gatekeeper.verify(any())).thenReturn(receipt());
        when(issuance.issue(any(), any())).thenThrow(new IssuanceException("CA down"));

        IssuanceResponse r = service.verifyAndIssue(request("YUBICO"));

        assertThat(r.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_ISSUANCE_FAILED);
        assertThat(r.getErrors()).containsExactly("CA down");
        assertThat(r.getVerifyReceipt().getVerificationId()).isEqualTo("v-1");
        ArgumentCaptor<IssuanceConfirmRequest> notice = ArgumentCaptor.forClass(IssuanceConfirmRequest.class);
        verify(gatekeeper).confirm(notice.capture());
        assertThat(notice.getValue().isIssued()).isFalse();
        assertThat(notice.getValue().getNonIssuanceReason()).isEqualTo("CA down");
        assertThat(notice.getValue().getConfirmationNonce()).isEqualTo("nonce");
    }

    @Test
    void aFailedTransportIssuanceHasNoReceipt() {
        CertificateRequest transport = request("YUBICO", null, null);
        transport.setCertificateType(CertificateType.TRANSPORT);
        when(issuance.issue(any(), any())).thenThrow(new IssuanceException("CA down"));

        IssuanceResponse r = service.verifyAndIssue(transport);

        assertThat(r.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_ISSUANCE_FAILED);
        assertThat(r.getVerifyReceipt()).isNull();
        verify(gatekeeper, never()).verify(any());
    }

    @Test
    void aSpentSignatureRefusesATransportIssuance() {
        CertificateRequest transport = request("YUBICO", null, null);
        transport.setCertificateType(CertificateType.TRANSPORT);
        when(bankId.consume(any(), any(), anyInt())).thenReturn(false);

        IssuanceResponse r = service.verifyAndIssue(transport);

        assertThat(r.getStage()).isEqualTo(IssuanceResponse.Stage.REJECTED_BANKID_ALREADY_USED);
        verify(issuance, never()).issue(any(), any());
    }

    @Test
    void aConfirmThatFailsLeavesTheCertificateIssuedWithTheLoopOpen() {
        when(gatekeeper.confirm(any())).thenThrow(new GatekeeperException("timeout"));

        IssuanceResponse r = issue(receipt());

        assertThat(r.getStage()).isEqualTo(IssuanceResponse.Stage.ISSUED_BUT_GATEKEEPER_CONFIRM_FAILED);
        assertThat(r.isIssued()).isTrue();
        assertThat(r.getErrors()).singleElement().asString().contains("timeout");
    }

    private String anomaly(Consumer<IssuanceConfirmResponse> change) {
        IssuanceConfirmResponse c = closed();
        change.accept(c);
        when(gatekeeper.confirm(any())).thenReturn(c);
        IssuanceResponse r = issue(receipt());
        assertThat(r.getStage()).isEqualTo(IssuanceResponse.Stage.ISSUED_BUT_CONFIRM_NOT_CLOSED);
        assertThat(r.getErrors()).hasSize(1);
        return r.getErrors().get(0);
    }

    @Test
    void eachWayAConfirmCanFailToCloseTheLoopIsNamed() {
        when(gatekeeper.confirm(any())).thenReturn(null);
        IssuanceResponse none = issue(receipt());
        assertThat(none.getStage()).isEqualTo(IssuanceResponse.Stage.ISSUED_BUT_CONFIRM_NOT_CLOSED);
        assertThat(none.getErrors()).singleElement().asString().contains("gatekeeper returned no confirm response");

        assertThat(anomaly(c -> c.setVerificationId("v-2")))
                .contains("confirm response carries verificationId v-2 but the verify-step receipt carries v-1");
        assertThat(anomaly(c -> c.setVerificationId(null)))
                .contains("confirm response carries verificationId null but the verify-step receipt carries v-1");
        assertThat(anomaly(c -> c.setRegistryStatus(null))).contains("confirm response carries no registryStatus");
        assertThat(anomaly(c -> c.setRegistryStatus(IssuanceConfirmResponse.RegistryStatus.VERIFIED_NOT_ISSUED)))
                .contains("gatekeeper approval registry ended in VERIFIED_NOT_ISSUED rather than VERIFIED_AND_ISSUED")
                .doesNotContain("(");
        assertThat(anomaly(c -> {
            c.setRegistryStatus(IssuanceConfirmResponse.RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
            c.setAnomalies(List.of("a", "b"));
        })).contains("rather than VERIFIED_AND_ISSUED (a; b)");
        assertThat(anomaly(c -> {
            c.setRegistryStatus(IssuanceConfirmResponse.RegistryStatus.ANOMALY_PUBLIC_KEY_MISMATCH);
            c.setAnomalies(null);
        })).contains("rather than VERIFIED_AND_ISSUED. ");
        assertThat(anomaly(c -> c.setLoopClosed(false))).contains("gatekeeper reported loopClosed=false");
        assertThat(anomaly(c -> c.setPublicKeyMatch(null)))
                .contains("gatekeeper did not report publicKeyMatch=true for the issued certificate (got null)");
    }

    // ---- receipt matching ------------------------------------------------------------------

    @Test
    void eachReceiptMismatchIsNamed() {
        Instant now = Instant.now();
        VerifyRequest sent = VerifyRequest.builder().hsmVendor("AZURE").countryCode("SE")
                .customerOrganisationNumber(ORG).customerSwishNumber(SWISH).keyPurpose("Swish SIGNING").build();
        VerifyResponse ok = receipt();
        ok.setVerificationTimestamp(now);
        // gatekeeper reports the vendor's name ("Microsoft"), not the token.
        ok.setHsmVendor(HsmVendor.AZURE.getVendorName());
        assertThat(AttestationService.receiptMismatch(ok, sent, now)).isNull();

        VerifyResponse r = receipt();
        r.setVerificationTimestamp(null);
        assertThat(AttestationService.receiptMismatch(r, sent, now)).isEqualTo("the receipt has no verificationTimestamp");
        r = receipt();
        r.setVerificationTimestamp(now.minusSeconds(301));
        assertThat(AttestationService.receiptMismatch(r, sent, now)).startsWith("verificationTimestamp ")
                .endsWith(" is more than PT5M from now");
        r = receipt();
        r.setCountryCode("NO");
        r.setVerificationTimestamp(now);
        assertThat(AttestationService.receiptMismatch(r, sent, now)).isEqualTo("countryCode NO is not SE");
        r = receipt();
        r.setVerificationTimestamp(now);
        r.setCustomerSwishNumber("1230000000");
        assertThat(AttestationService.receiptMismatch(r, sent, now))
                .isEqualTo("customerSwishNumber 1230000000 is not " + SWISH);
        r = receipt();
        r.setVerificationTimestamp(now);
        r.setKeyPurpose("Swish TRANSPORT");
        assertThat(AttestationService.receiptMismatch(r, sent, now))
                .isEqualTo("keyPurpose Swish TRANSPORT is not Swish SIGNING");
        r = receipt();
        r.setVerificationTimestamp(now);
        r.setHsmVendor("Yubico");
        assertThat(AttestationService.receiptMismatch(r, sent, now)).isEqualTo("hsmVendor Yubico is not AZURE");
        // An unknown vendor token has no vendor name; an empty one in the receipt does not stand in for it.
        r = receipt();
        r.setVerificationTimestamp(now);
        r.setHsmVendor("");
        VerifyRequest unknownVendor = VerifyRequest.builder().hsmVendor("ACME").countryCode("SE")
                .customerOrganisationNumber(ORG).customerSwishNumber(SWISH).keyPurpose("Swish SIGNING").build();
        assertThat(AttestationService.receiptMismatch(r, unknownVendor, now)).isEqualTo("hsmVendor  is not ACME");
        r = receipt();
        r.setVerificationTimestamp(now);
        r.setHsmVendor("AZURE");
        r.setKeyProperties(null);
        assertThat(AttestationService.receiptMismatch(r, sent, now)).isEqualTo("keyProperties null contradict compliance");
    }
}
