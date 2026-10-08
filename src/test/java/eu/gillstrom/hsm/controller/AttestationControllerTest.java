package eu.gillstrom.hsm.controller;

import eu.gillstrom.hsm.gatekeeper.IssuanceConfirmResponse;
import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.model.HsmVendor;
import eu.gillstrom.hsm.model.IssuanceResponse;
import eu.gillstrom.hsm.service.AttestationService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The controller's three endpoints, and the small model accessors they and
 * the service rely on.
 */
class AttestationControllerTest {

    @Test
    void verifyAndIssueReturnsTheServicesOutcome() {
        AttestationService service = mock(AttestationService.class);
        IssuanceResponse outcome = IssuanceResponse.builder()
                .stage(IssuanceResponse.Stage.REJECTED_LOCAL_VERIFICATION).build();
        when(service.verifyAndIssue(any(CertificateRequest.class), isNull())).thenReturn(outcome);

        var response = new AttestationController(service)
                .verifyAndIssue(new CertificateRequest(), new MockHttpServletRequest());

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isSameAs(outcome);
    }

    @Test
    void healthAndVendors() {
        AttestationController controller = new AttestationController(mock(AttestationService.class));

        assertThat(controller.health().getBody()).isEqualTo("OK");
        assertThat(controller.vendors().getBody())
                .containsExactly(Arrays.stream(HsmVendor.values()).map(Enum::name).toArray(String[]::new));
    }

    @Test
    void eachVendorHasItsProductName() {
        assertThat(HsmVendor.ENTRUST.getProductName()).isEqualTo("nShield");
        assertThat(HsmVendor.YUBICO.getProductName()).isEqualTo("YubiHSM 2");
    }

    @Test
    void attestationEvidenceIsNonBlankDataOrANonEmptyChain() {
        CertificateRequest r = new CertificateRequest();
        assertThat(r.hasAttestationEvidence()).isFalse();
        r.setAttestationData(" ");
        r.setAttestationCertChain(List.of());
        assertThat(r.hasAttestationEvidence()).isFalse();
        r.setAttestationCertChain(List.of("c"));
        assertThat(r.hasAttestationEvidence()).isTrue();
        r.setAttestationCertChain(null);
        r.setAttestationData("d");
        assertThat(r.hasAttestationEvidence()).isTrue();
    }

    @Test
    void aConfirmSummaryCopiesTheResponseAndIsAbsentWithoutOne() {
        assertThat(IssuanceResponse.IssuanceConfirmResponseSummary.from(null)).isNull();

        var summary = IssuanceResponse.IssuanceConfirmResponseSummary.from(IssuanceConfirmResponse.builder()
                .verificationId("v").loopClosed(true).publicKeyMatch(true)
                .registryStatus(IssuanceConfirmResponse.RegistryStatus.VERIFIED_AND_ISSUED).build());
        assertThat(summary.getVerificationId()).isEqualTo("v");
        assertThat(summary.isLoopClosed()).isTrue();
    }
}
