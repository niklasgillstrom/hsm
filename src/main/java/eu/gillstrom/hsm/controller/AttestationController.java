package eu.gillstrom.hsm.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import eu.gillstrom.hsm.model.CertificateRequest;
import eu.gillstrom.hsm.model.IssuanceResponse;
import eu.gillstrom.hsm.model.VerificationResponse;
import eu.gillstrom.hsm.service.AttestationService;

@RestController
@RequestMapping("/api/v1/attestation")
@Tag(name = "HSM Attestation", description = "HSM attestation verification for Swish certificate requests")
public class AttestationController {
    
    private final AttestationService attestationService;
    
    public AttestationController(AttestationService attestationService) {
        this.attestationService = attestationService;
    }
    
    @PostMapping("/verify")
    @Operation(
        summary = "Verify HSM attestation",
        description = "Verifies that a CSR's public key was generated inside a genuine HSM by validating the attestation certificate chain and BankID signature",
        responses = {
            @ApiResponse(responseCode = "200", description = "Verification completed",
                content = @Content(schema = @Schema(implementation = VerificationResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid request")
        }
    )
    public ResponseEntity<VerificationResponse> verify(@Valid @RequestBody CertificateRequest request) {
        VerificationResponse response = attestationService.verify(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verifyAndIssue")
    @Operation(
        summary = "Verify, gatekeeper-verify, issue, and gatekeeper-confirm",
        description = "Runs the four-phase supervisory issuance flow: (1) local "
                + "HSM-attestation verification, (2) gatekeeper.verify — POST canonical "
                + "evidence to the configured gatekeeper and verify the returned signed "
                + "receipt against the trusted gatekeeper certificate registry, (3) "
                + "issuance via the configured IssuanceClient, (4) gatekeeper.confirm — "
                + "POST the issued certificate back so the gatekeeper can confirm the "
                + "public key matches and close its supervisory loop. SIGNING certificates "
                + "require all four phases; TRANSPORT certificates skip both gatekeeper "
                + "phases. Reference defaults are fail-closed for the gatekeeper (no "
                + "client configured -> SIGNING fails) and mock for issuance (in-process "
                + "test CA).",
        responses = {
            @ApiResponse(responseCode = "200", description = "Outcome of the flow — "
                    + "stage indicates which phase produced the final result",
                content = @Content(schema = @Schema(implementation = IssuanceResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid request")
        }
    )
    public ResponseEntity<IssuanceResponse> verifyAndIssue(@Valid @RequestBody CertificateRequest request) {
        IssuanceResponse response = attestationService.verifyAndIssue(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    @Operation(summary = "Health check")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK");
    }
    
    @GetMapping("/vendors")
    @Operation(summary = "List supported HSM vendors")
    public ResponseEntity<String[]> vendors() {
        return ResponseEntity.ok(new String[]{"YUBICO", "SECUROSYS", "AZURE", "GOOGLE"});
    }
}
