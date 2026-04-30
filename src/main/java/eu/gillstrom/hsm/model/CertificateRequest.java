package eu.gillstrom.hsm.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import eu.gillstrom.hsm.model.VerificationResponse.CertificateType;

import java.util.List;

@Data
public class CertificateRequest {

    @NotBlank(message = "CSR is required")
    private String csr;

    @NotBlank(message = "BankID signature is required")
    private String bankIdSignatureResponse;

    private String bankIdOcspResponse;

    @NotBlank(message = "Organisation number is required")
    @Pattern(regexp = "^\\d{10}(\\d{2})?$", message = "Organisation number must be 10 or 12 digits")
    private String organisationNumber;

    @NotBlank(message = "Swish number is required")
    @Pattern(regexp = "^(123|987)\\d{7}$", message = "Swish number must start with 123 or 987 followed by 7 digits")
    private String swishNumber;

    /**
     * Explicit certificate type. The server enforces that {@link CertificateType#SIGNING}
     * requests carry complete HSM attestation evidence; any attempt to request a SIGNING
     * certificate without attestation is rejected regardless of what other fields are
     * present. A TRANSPORT request must not carry attestation data — if it does, the
     * request is rejected as ambiguous.
     */
    @NotNull(message = "certificateType is required (SIGNING or TRANSPORT)")
    private CertificateType certificateType;

    // HSM Vendor - required for signing certificates
    private String hsmVendor; // YUBICO, SECUROSYS, AZURE, GOOGLE

    // === HSM Attestation Data (vendor-specific) ===

    // Yubico: attestation certificate (contains public key)
    // Securosys: XML attestation file (base64)
    // Cloud HSMs: attestation document
    private String attestationData;

    // Securosys only: signature file (.sig) base64
    private String attestationSignature;

    // Certificate chain (excluding root which is on server)
    // Yubico: [attestation_cert, device_cert, intermediate_cert]
    // Securosys: [attestation_cert, device_cert]
    private List<String> attestationCertChain;

    /**
     * Structural presence check used by the server to detect mismatches between
     * {@link #certificateType} and the supplied attestation fields. Callers
     * outside the server should not use this to decide certificate type —
     * that decision is owned by the server based on the explicit
     * {@link #certificateType} field.
     */
    public boolean hasAttestationEvidence() {
        return (attestationData != null && !attestationData.isBlank())
                || (attestationCertChain != null && !attestationCertChain.isEmpty());
    }
}
