package eu.gillstrom.hsm.service;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link BankIdService}. These are intentionally negative-path
 * tests; producing a real BankID envelope would require the Finansiell ID-
 * Teknik PKI which is not available to the test harness. The service's
 * {@link BankIdService#verify(String, String)} is contractually obliged to
 * return {@code valid=false} rather than throw on malformed inputs.
 */
class BankIdServiceTest {

    @Test
    void invalidBase64InputReturnsInvalid() {
        BankIdService service = new BankIdService(false);

        BankIdService.BankIdResult result = service.verify("not-valid-base64!!!", null);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getError()).isNotBlank();
    }

    @Test
    void xmlWithoutSignatureElementReturnsInvalidWithDsigError() {
        BankIdService service = new BankIdService(false);

        // Well-formed XML but no <Signature> element and no certificates.
        String xml = "<bankIdSignedData><signingTime>2026-01-01T00:00:00Z</signingTime></bankIdSignedData>";
        String xmlBase64 = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));

        BankIdService.BankIdResult result = service.verify(xmlBase64, null);

        assertThat(result.isValid()).isFalse();
        // The service walks the chain-extraction path first; with no
        // X509Certificate present the error will reference that, with an
        // XML-DSig Signature also missing the message references signature
        // or certificate. Either is a legitimate "missing cryptographic
        // material" error.
        assertThat(result.getError()).isNotBlank();
        assertThat(result.getError().toLowerCase())
                .containsAnyOf("signature", "x509", "certificate");
    }

    @Test
    void emptyInputReturnsInvalid() {
        BankIdService service = new BankIdService(false);

        BankIdService.BankIdResult result = service.verify("", null);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getError()).isNotBlank();
    }

    /**
     * The parser refuses any DOCTYPE, so neither an external entity (XXE,
     * here pointing at a local file) nor an entity-expansion bomb is ever
     * resolved. The error names the DOCTYPE: the refusal comes from the
     * parser, not from a later failure of the signature check.
     */
    @Test
    void aDoctypeIsRefusedByTheParser() {
        BankIdService service = new BankIdService(false);
        String[] documents = {
            "<?xml version=\"1.0\"?><!DOCTYPE d [<!ENTITY x SYSTEM \"file:///etc/hostname\">]>"
                + "<bankIdSignedData><usrVisibleData>&x;</usrVisibleData></bankIdSignedData>",
            "<?xml version=\"1.0\"?><!DOCTYPE d [<!ENTITY a \"aaaaaaaaaa\">"
                + "<!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">]>"
                + "<bankIdSignedData><usrVisibleData>&c;</usrVisibleData></bankIdSignedData>",
            "<?xml version=\"1.0\"?><!DOCTYPE d SYSTEM \"http://127.0.0.1:9/external.dtd\">"
                + "<bankIdSignedData/>"};
        for (String xml : documents) {
            BankIdService.BankIdResult result = service.verify(
                    Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8)), null);

            assertThat(result.isValid()).as(xml).isFalse();
            assertThat(result.getError()).as(xml).startsWith("Parse error").contains("DOCTYPE");
        }
    }
}
