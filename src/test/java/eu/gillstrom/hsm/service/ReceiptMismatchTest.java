package eu.gillstrom.hsm.service;

import eu.gillstrom.hsm.gatekeeper.VerifyRequest;
import eu.gillstrom.hsm.gatekeeper.VerifyResponse;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class ReceiptMismatchTest {

    private static final Instant NOW = Instant.parse("2026-10-06T12:00:00Z");

    private static VerifyResponse receipt(String vendor) {
        return VerifyResponse.builder()
                .verificationTimestamp(NOW)
                .countryCode("SE")
                .supplierIdentifier("5569743098")
                .keyPurpose("Swish SIGNING")
                .hsmVendor(vendor)
                .keyProperties(new VerifyResponse.KeyProperties(true, false, true, true))
                .build();
    }

    private static VerifyRequest sent(String vendor) {
        return VerifyRequest.builder()
                .countryCode("SE")
                .supplierIdentifier("5569743098")
                .keyPurpose("Swish SIGNING")
                .hsmVendor(vendor)
                .build();
    }

    @Test
    void gatekeeperReportsTheVendorsNameNotItsToken() {
        // gatekeeper answers hsmVendor with HsmVendor.getVendorName().
        assertThat(AttestationService.receiptMismatch(receipt("Microsoft"), sent("AZURE"), NOW)).isNull();
        assertThat(AttestationService.receiptMismatch(receipt("Google Cloud"), sent("google"), NOW)).isNull();
        assertThat(AttestationService.receiptMismatch(receipt("AZURE"), sent("AZURE"), NOW)).isNull();
        assertThat(AttestationService.receiptMismatch(receipt("Thales"), sent("AZURE"), NOW))
                .startsWith("hsmVendor Thales is not AZURE");
        assertThat(AttestationService.receiptMismatch(receipt("Microsoft"), sent("UNKNOWN"), NOW))
                .startsWith("hsmVendor");
        assertThat(AttestationService.receiptMismatch(receipt(null), sent("AZURE"), NOW)).startsWith("hsmVendor");
    }
}
