package eu.gillstrom.hsm.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import eu.gillstrom.hsm.gatekeeper.GatekeeperClient;
import eu.gillstrom.hsm.gatekeeper.ReceiptVerifier;
import eu.gillstrom.hsm.issuance.IssuanceClient;
import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.model.VerificationResponse;
import eu.gillstrom.hsm.model.VerificationResponse.CertificateType;
import eu.gillstrom.hsm.service.AttestationService;
import eu.gillstrom.hsm.service.BankIdConsentPolicy;
import eu.gillstrom.hsm.service.BankIdService;
import eu.gillstrom.hsm.service.CallerPolicy;
import eu.gillstrom.hsm.service.KeyPolicy;
import eu.gillstrom.hsm.service.SignatoryRightsVerifier;
import eu.gillstrom.hsm.testsupport.TestPki;
import eu.gillstrom.hsm.util.Csrs;
import eu.gillstrom.hsm.verification.AzureHsmVerifier;
import eu.gillstrom.hsm.verification.Crypto4AVerifier;
import eu.gillstrom.hsm.verification.FortanixVerifier;
import eu.gillstrom.hsm.verification.GoogleCloudHsmVerifier;
import eu.gillstrom.hsm.verification.MarvellHsmVerifier;
import eu.gillstrom.hsm.verification.NShieldVerifier;
import eu.gillstrom.hsm.verification.SecurosysVerifier;
import eu.gillstrom.hsm.verification.TestVerifiers;
import eu.gillstrom.hsm.verification.ThalesLunaVerifier;
import eu.gillstrom.hsm.verification.YubicoVerifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * End-to-end verifier tests against real attestation fixtures produced by
 * the reference hardware. See {@code examples/README.md} for fixture
 * provenance and the reproducibility contract.
 *
 * <p>These tests prove two things that the synthetic {@code TestPki}-based tests
 * cannot prove on their own:
 * <ol>
 *   <li><b>Happy path</b>: a real attestation produced by a real Securosys/Yubico
 *       device, verified against the pinned vendor root, returns {@code valid=true}
 *       with the expected attested attributes.</li>
 *   <li><b>Binding step</b>: substituting a different CSR public key against the
 *       same real attestation chain causes {@code publicKeyMatch=false} and the
 *       overall result to be {@code valid=false}. This is what prevents an
 *       attacker from re-using a stolen attestation for a software-held key.</li>
 * </ol>
 *
 * <p>The fixtures live under {@code examples/<vendor>/} at the repository root.
 * If they are missing (e.g., a fork that did not pull the example data), the
 * happy-path tests are skipped via {@link EnabledIf}; the negative tests are
 * skipped only if the fixture itself is missing because they re-use the real
 * attestation chain to demonstrate that the binding fails for the wrong CSR.
 */
class RealAttestationFixtureTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Path YUBICO_REQUEST = Paths.get("examples/yubico/request.json");
    private static final Path YUBICO_EXPECTED = Paths.get("examples/yubico/expected.json");
    private static final Path SECUROSYS_REQUEST = Paths.get("examples/securosys/request.json");
    private static final Path SECUROSYS_EXPECTED = Paths.get("examples/securosys/expected.json");

    static boolean yubicoFixturePresent() {
        return Files.exists(YUBICO_REQUEST) && Files.exists(YUBICO_EXPECTED);
    }

    static boolean securosysFixturePresent() {
        return Files.exists(SECUROSYS_REQUEST) && Files.exists(SECUROSYS_EXPECTED);
    }

    // ------------------------------------------------------------------ Yubico

    @Test
    @EnabledIf("yubicoFixturePresent")
    void yubicoFixtureHappyPath() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(YUBICO_REQUEST));
        JsonNode exp = MAPPER.readTree(Files.readString(YUBICO_EXPECTED));

        List<String> chain = readPemList(req.get("attestationCertChain"));
        PublicKey csrPublicKey = parseCsrPublicKey(req.get("csr").asText());

        YubicoVerifier verifier = new YubicoVerifier();
        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(chain, csrPublicKey);

        // Assertions sourced from the captured production response.
        assertThat(r.isChainValid())
                .as("chain should anchor at the pinned Yubico Root CA")
                .isEqualTo(exp.get("attestationChainValid").asBoolean());
        assertThat(r.isPublicKeyMatch())
                .as("attested public key must match CSR public key")
                .isEqualTo(exp.get("publicKeyMatch").asBoolean());
        assertThat(r.getKeyOrigin())
                .as("attested keyOrigin")
                .isEqualTo(exp.get("keyOrigin").asText());
        assertThat(r.isKeyExportable())
                .as("attested keyExportable")
                .isEqualTo(exp.get("keyExportable").asBoolean());
        assertThat(r.isValid())
                .as("overall attestation result")
                .isEqualTo(exp.get("valid").asBoolean());
        assertThat(r.getDeviceSerial())
                .as("device serial extracted from per-device attestation CA subject")
                .isEqualTo(exp.get("hsmSerialNumber").asText());
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void yubicoFixtureRejectsCsrForDifferentKey() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(YUBICO_REQUEST));
        List<String> chain = readPemList(req.get("attestationCertChain"));

        // Replace the CSR's public key with a synthetic one. The attestation
        // chain itself is unchanged and still validates; only the CSR-binding
        // step should fail.
        KeyPair other = TestPki.newRsaKeyPair(2048);

        YubicoVerifier verifier = new YubicoVerifier();
        YubicoVerifier.YubicoAttestationResult r =
                verifier.verifyYubicoAttestation(chain, other.getPublic());

        assertThat(r.isChainValid())
                .as("chain itself is real and still validates")
                .isTrue();
        assertThat(r.isPublicKeyMatch())
                .as("CSR for wrong key must not bind to attested key")
                .isFalse();
        assertThat(r.isValid())
                .as("overall result must be invalid when binding fails")
                .isFalse();
    }

    // -------------------------------------------------------------- Securosys

    @Test
    @EnabledIf("securosysFixturePresent")
    void securosysFixtureHappyPath() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(SECUROSYS_REQUEST));
        JsonNode exp = MAPPER.readTree(Files.readString(SECUROSYS_EXPECTED));

        String xmlBase64 = req.get("attestationData").asText();
        String sigBase64 = req.get("attestationSignature").asText();
        List<String> chain = readPemList(req.get("attestationCertChain"));
        PublicKey csrPublicKey = parseCsrPublicKey(req.get("csr").asText());

        SecurosysVerifier verifier = new SecurosysVerifier();
        SecurosysVerifier.SecurosysAttestationResult r =
                verifier.verifySecurosysAttestation(xmlBase64, sigBase64, chain, csrPublicKey);

        assertThat(r.isChainValid())
                .as("chain should anchor at the pinned Securosys Primus Root CA")
                .isEqualTo(exp.get("attestationChainValid").asBoolean());
        assertThat(r.isSignatureValid())
                .as("XML signature should verify under attested public key")
                .isTrue();
        assertThat(r.isPublicKeyMatch())
                .as("attested public key (XML public_key element) must match CSR")
                .isEqualTo(exp.get("publicKeyMatch").asBoolean());
        assertThat(r.isExtractable())
                .as("attested key must NOT be extractable")
                .isFalse();
        assertThat(r.isNeverExtractable())
                .as("attested key must be never_extractable")
                .isTrue();
        assertThat(r.isSensitive())
                .as("attested key must be sensitive")
                .isTrue();
        assertThat(r.isAlwaysSensitive())
                .as("attested key must be always_sensitive")
                .isTrue();
        assertThat(r.getKeyOrigin())
                .as("creation attribute of the attested key")
                .isEqualTo(exp.get("keyOrigin").asText());
        assertThat(r.isValid())
                .as("overall attestation result")
                .isEqualTo(exp.get("valid").asBoolean());
        assertThat(r.getHsmSerialNumber())
                .as("HSM serial extracted from issuing CA subject CN")
                .isEqualTo(exp.get("hsmSerialNumber").asText());
    }

    @Test
    @EnabledIf("securosysFixturePresent")
    void securosysFixtureRejectsCsrForDifferentKey() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(SECUROSYS_REQUEST));
        String xmlBase64 = req.get("attestationData").asText();
        String sigBase64 = req.get("attestationSignature").asText();
        List<String> chain = readPemList(req.get("attestationCertChain"));

        KeyPair other = TestPki.newRsaKeyPair(2048);

        SecurosysVerifier verifier = new SecurosysVerifier();
        SecurosysVerifier.SecurosysAttestationResult r =
                verifier.verifySecurosysAttestation(xmlBase64, sigBase64, chain, other.getPublic());

        assertThat(r.isChainValid()).as("chain itself is real and still validates").isTrue();
        assertThat(r.isSignatureValid()).as("XML signature is real and still verifies").isTrue();
        assertThat(r.isPublicKeyMatch())
                .as("CSR for wrong key must not bind to attested key")
                .isFalse();
        assertThat(r.isValid())
                .as("overall result must be invalid when binding fails")
                .isFalse();
    }

    // ------------------------------------------------- proof of possession (a)

    @Test
    @EnabledIf("yubicoFixturePresent")
    void yubicoFixtureCsrPassesProofOfPossession() throws Exception {
        assertProofOfPossession(YUBICO_REQUEST, "YUBICO", YUBICO_EXPECTED);
    }

    @Test
    @EnabledIf("securosysFixturePresent")
    void securosysFixtureCsrPassesProofOfPossession() throws Exception {
        assertProofOfPossession(SECUROSYS_REQUEST, "SECUROSYS", SECUROSYS_EXPECTED);
    }

    /**
     * The fixture's CSR signature verifies under the public key the CSR
     * carries. {@code AttestationService.csrSignatureValid} is private, so its
     * check is mirrored here (BouncyCastle content verifier built from the
     * CSR's own SubjectPublicKeyInfo); the fixture is then also run through
     * {@link AttestationService#verify}, which applies that same check and
     * would report {@code CSR_SIGNATURE_INVALID}.
     */
    private static void assertProofOfPossession(Path request, String vendor, Path expected) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        JsonNode req = MAPPER.readTree(Files.readString(request));
        PKCS10CertificationRequest csr = Csrs.parse(req.get("csr").asText());
        assertThat(popValid(csr)).as("CSR signature under its own public key").isTrue();

        // Negative control: the same check refuses the CSR once one bit of its
        // signature (the last byte of the DER encoding) is flipped.
        byte[] tampered = csr.getEncoded();
        tampered[tampered.length - 1] ^= 0x01;
        assertThat(popValid(new PKCS10CertificationRequest(tampered))).as("tampered signature").isFalse();

        VerificationResponse r = service(KeyPolicy.defaults()).verify(certificateRequest(req, vendor));
        assertThat(r.getErrors()).as("errors").isEmpty();
        assertThat(r.isValid()).as("valid").isTrue();
        assertThat(r.getCsrPublicKeyFingerprint())
                .isEqualTo(MAPPER.readTree(Files.readString(expected)).get("csrPublicKeyFingerprint").asText());
    }

    private static boolean popValid(PKCS10CertificationRequest csr) throws Exception {
        return csr.isSignatureValid(new JcaContentVerifierProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(csr.getSubjectPublicKeyInfo()));
    }

    // ------------------------------------------- a different pinned root (b)

    @Test
    @EnabledIf("yubicoFixturePresent")
    void yubicoFixtureIsRejectedUnderADifferentPinnedRoot() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(YUBICO_REQUEST));
        List<String> chain = readPemList(req.get("attestationCertChain"));
        PublicKey csrPublicKey = parseCsrPublicKey(req.get("csr").asText());

        // A substitute root with the real root's exact name (CN=Yubico YubiHSM
        // Root CA) but its own key: the anchor is bound by key, not by name.
        X509Certificate realIssuer = parse(chain.get(chain.size() - 1));
        X509Certificate substitute = TestPki.selfSignedCa(TestPki.newRsaKeyPair(2048), "Yubico YubiHSM Root CA");
        assertThat(substitute.getSubjectX500Principal()).isEqualTo(realIssuer.getIssuerX500Principal());

        YubicoVerifier.YubicoAttestationResult r =
                TestVerifiers.yubicoAnchoredAt(substitute).verifyYubicoAttestation(chain, csrPublicKey);

        assertThat(r.isChainValid()).as("chain does not validate to the substitute root").isFalse();
        assertThat(r.isValid()).isFalse();
        assertThat(r.isPublicKeyMatch()).as("only the anchor changed").isTrue();
        assertThat(r.getErrors()).contains("Certificate chain verification failed");
    }

    @Test
    @EnabledIf("securosysFixturePresent")
    void securosysFixtureIsRejectedUnderADifferentPinnedRoot() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(SECUROSYS_REQUEST));
        List<String> chain = readPemList(req.get("attestationCertChain"));
        PublicKey csrPublicKey = parseCsrPublicKey(req.get("csr").asText());

        // A substitute root with the real root's exact subject name but its own key.
        X509Certificate realIssuer = parse(chain.get(chain.size() - 1));
        X509Certificate substitute = TestPki.withSubject(
                X500Name.getInstance(realIssuer.getIssuerX500Principal().getEncoded()));
        assertThat(substitute.getSubjectX500Principal()).isEqualTo(realIssuer.getIssuerX500Principal());

        SecurosysVerifier.SecurosysAttestationResult r = TestVerifiers.securosysAnchoredAt(substitute)
                .verifySecurosysAttestation(req.get("attestationData").asText(),
                        req.get("attestationSignature").asText(), chain, csrPublicKey);

        assertThat(r.isChainValid()).as("chain does not validate to the substitute root").isFalse();
        assertThat(r.isValid()).isFalse();
        assertThat(r.isSignatureValid()).as("only the anchor changed").isTrue();
        assertThat(r.isPublicKeyMatch()).as("only the anchor changed").isTrue();
        assertThat(r.getErrors()).contains("Certificate chain verification failed");
    }

    // ------------------------------------------------ unknown vendor token (c)

    @Test
    @EnabledIf("yubicoFixturePresent")
    void yubicoFixtureWithAnUnknownVendorTokenIsRefusedByTheVendorRouter() throws Exception {
        assertUnknownVendorRefused(YUBICO_REQUEST, "YUBICO");
    }

    @Test
    @EnabledIf("securosysFixturePresent")
    void securosysFixtureWithAnUnknownVendorTokenIsRefusedByTheVendorRouter() throws Exception {
        assertUnknownVendorRefused(SECUROSYS_REQUEST, "SECUROSYS");
    }

    /** As {@code AttestationServiceDispatchTest.anUnknownOrMissingVendorIsRefused}, with real evidence. */
    private static void assertUnknownVendorRefused(Path request, String realToken) throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(request));
        AttestationService service = service(KeyPolicy.defaults());
        for (String vendor : new String[] {"acme", realToken + "2", "YubiHSM 2", "Primus HSM"}) {
            VerificationResponse r = service.verify(certificateRequest(req, vendor));
            assertThat(r.getErrors()).as(vendor).containsExactly("hsmVendor is required for signing certificates");
            assertThat(r.isValid()).as(vendor).isFalse();
            assertThat(r.getHsmVendor()).as(vendor).isNull();
            assertThat(r.isAttestationChainValid()).as(vendor).isFalse();
        }
        // The same evidence under its own token is accepted.
        assertThat(service.verify(certificateRequest(req, realToken.toLowerCase())).isValid()).isTrue();
    }

    // ---------------------------------------- firmware and FIPS reporting (d)

    @Test
    @EnabledIf("yubicoFixturePresent")
    void yubicoFixtureReportsFirmwareAndFipsIndicatorButNoFipsApprovedFlag() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(YUBICO_REQUEST));
        YubicoVerifier.YubicoAttestationResult r = new YubicoVerifier().verifyYubicoAttestation(
                readPemList(req.get("attestationCertChain")), parseCsrPublicKey(req.get("csr").asText()));
        assertThat(r.getFirmware()).isEqualTo("2.2.0");
        // 41482.4.10 sits on the device attestation certificate (chain[1]), not on the key certificate.
        assertThat(r.getFipsIndicator()).isEqualTo(5);
        // 41482.4.12 is on neither certificate.
        assertThat(r.getFipsApprovedMode()).isNull();
        assertThat(r.isValid()).as("absence of the FIPS-approved flag does not change valid").isTrue();

        VerificationResponse v = service(KeyPolicy.defaults()).verify(certificateRequest(req, "YUBICO"));
        assertThat(v.isValid()).isTrue();
        assertThat(v.getHsmFirmwareVersion()).isEqualTo("2.2.0");
        assertThat(v.getHsmFipsIndicator()).isEqualTo(5);
        assertThat(v.getHsmFipsApprovedMode()).isNull();
    }

    @Test
    @EnabledIf("securosysFixturePresent")
    void securosysFixtureReportsNoFirmwareOrFipsFields() throws Exception {
        JsonNode req = MAPPER.readTree(Files.readString(SECUROSYS_REQUEST));
        VerificationResponse v = service(KeyPolicy.defaults()).verify(certificateRequest(req, "SECUROSYS"));
        assertThat(v.isValid()).isTrue();
        assertThat(v.getHsmFirmwareVersion()).isNull();
        assertThat(v.getHsmFipsIndicator()).isNull();
        assertThat(v.getHsmFipsApprovedMode()).isNull();
    }

    @Test
    @EnabledIf("yubicoFixturePresent")
    void requiringFipsApprovedModeRefusesBothRealFixtures() throws Exception {
        KeyPolicy require = new KeyPolicy(KeyPolicy.DEFAULT_ALLOWED_KEYS,
                KeyPolicy.DEFAULT_ALLOWED_CSR_SIGNATURE_ALGORITHMS, true);

        VerificationResponse yubico = service(require).verify(
                certificateRequest(MAPPER.readTree(Files.readString(YUBICO_REQUEST)), "YUBICO"));
        assertThat(yubico.isValid()).isFalse();
        assertThat(yubico.getErrors()).singleElement().asString()
                .startsWith(KeyPolicy.FIPS_APPROVED_MODE_NOT_ATTESTED + ": ");
        assertThat(yubico.getHsmFipsIndicator()).isEqualTo(5);

        if (securosysFixturePresent()) {
            VerificationResponse securosys = service(require).verify(
                    certificateRequest(MAPPER.readTree(Files.readString(SECUROSYS_REQUEST)), "SECUROSYS"));
            assertThat(securosys.isValid()).isFalse();
            assertThat(securosys.getErrors()).singleElement().asString()
                    .startsWith(KeyPolicy.FIPS_MODE_NOT_IN_ATTESTATION_FORMAT + ": ");
        }
    }

    // ----------------------------------------------------------------- helpers

    private static final String ORG = "5569743098";
    private static final String SWISH = "1231015932";

    /**
     * An {@link AttestationService} with the real vendor verifiers; BankID,
     * signatory rights and the consent policy are stubbed to pass, as in
     * {@code AttestationServiceDispatchTest}, so that what is tested is the
     * CSR check, the vendor router and the attestation verification.
     */
    private static AttestationService service(KeyPolicy keyPolicy) {
        BankIdService bankId = mock(BankIdService.class);
        BankIdService.BankIdResult ok = new BankIdService.BankIdResult();
        ok.setValid(true);
        ok.setSignatureValid(true);
        ok.setCertificateChainValid(true);
        ok.setPersonalNumber("190001019999");
        ok.setUsrNonVisibleData(new BankIdService.Mandate(ORG, SWISH, 1).canonical());
        ok.setSignatureTime(Instant.now());
        when(bankId.verify(any(), any())).thenReturn(ok);
        return new AttestationService(bankId, new SecurosysVerifier(), new YubicoVerifier(),
                new AzureHsmVerifier(), new GoogleCloudHsmVerifier(), new MarvellHsmVerifier(),
                new ThalesLunaVerifier(), new Crypto4AVerifier(), new FortanixVerifier(), new NShieldVerifier(),
                (p, o, s) -> SignatoryRightsVerifier.Result.authorised("test"),
                mock(GatekeeperClient.class), mock(ReceiptVerifier.class), mock(IssuanceClient.class),
                keyPolicy, mock(BankIdConsentPolicy.class), CallerPolicy.off(), "SE");
    }

    /** A SIGNING request carrying the fixture's CSR and evidence, for the organisation the CSR names. */
    private static CertificateRequest certificateRequest(JsonNode req, String vendor) {
        CertificateRequest r = new CertificateRequest();
        r.setCsr(req.get("csr").asText());
        r.setCertificateType(CertificateType.SIGNING);
        r.setHsmVendor(vendor);
        if (req.hasNonNull("attestationData")) {
            r.setAttestationData(req.get("attestationData").asText());
        }
        if (req.hasNonNull("attestationSignature")) {
            r.setAttestationSignature(req.get("attestationSignature").asText());
        }
        r.setAttestationCertChain(readPemList(req.get("attestationCertChain")));
        r.setOrganisationNumber(ORG);
        r.setSwishNumber(SWISH);
        r.setBankIdSignatureResponse("signature");
        r.setBankIdOcspResponse("ocsp");
        return r;
    }

    private static X509Certificate parse(String pem) throws Exception {
        String text = pem.trim().startsWith("-----BEGIN") ? pem.trim()
                : "-----BEGIN CERTIFICATE-----\n" + pem.trim() + "\n-----END CERTIFICATE-----";
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(text.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    }

    private static List<String> readPemList(JsonNode arr) {
        List<String> out = new ArrayList<>(arr.size());
        for (JsonNode n : arr) {
            out.add(n.asText());
        }
        return out;
    }

    private static PublicKey parseCsrPublicKey(String csrPem) throws Exception {
        // Strip PEM armour and decode body.
        String body = csrPem
                .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(body);
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(der);
        return new JcaPKCS10CertificationRequest(csr).getPublicKey();
    }
}
