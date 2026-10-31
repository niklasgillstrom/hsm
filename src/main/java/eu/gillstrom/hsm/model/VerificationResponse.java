package eu.gillstrom.hsm.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
@Builder
public class VerificationResponse {

    private boolean valid;
    private CertificateType certificateType;

    // CSR
    private String csrPublicKeyFingerprint;
    private String csrPublicKeyAlgorithm;

    // HSM attestation (SIGNING certificates only)
    private String attestedPublicKeyFingerprint;
    private String hsmVendor;
    private String hsmModel;
    private String hsmSerialNumber;
    // What the attestation states about the HSM's firmware and FIPS mode. Yubico only
    // (firmware 1.3.6.1.4.1.41482.4.1, FIPS indicator .4.10, FIPS-approved
    // .4.12), and only from a chain that validated to the pinned root; null
    // otherwise and for every other vendor.
    private String hsmFirmwareVersion;
    private Integer hsmFipsIndicator;
    private Boolean hsmFipsApprovedMode;
    private boolean publicKeyMatch;
    private boolean attestationChainValid;

    // Key attributes (critical for security)
    private String keyOrigin; // "generated", "imported", "imported_wrapped", if not generated on the device all security guarantees are void
    private boolean keyExportable; // true = ERROR, the key can be exported, thus all security guarantees are void

    // BankID - signature
    private boolean bankIdSignatureValid;
    private boolean bankIdCertificateChainValid;
    private int bankIdCertificateCount;

    // BankID - signer
    private String bankIdPersonalNumber;
    private String bankIdName;

    // BankID - signed data
    private String bankIdUsrVisibleData;
    private String bankIdUsrNonVisibleData;

    // BankID - Relying Party (the organization the individual signed with)
    private String bankIdRelyingPartyName;
    private String bankIdRelyingPartyOrgNumber;

    // BankID - Signing time (certificate validation time)
    private Instant bankIdSignatureTime;

    // Request data
    private String organisationNumber;
    private String swishNumber;
    private boolean authorizedSignatory;

    private List<String> errors;
    private List<String> warnings;

    public enum CertificateType {
        TRANSPORT,
        SIGNING
    }
}