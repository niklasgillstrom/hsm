package eu.gillstrom.hsm.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Client for the DORA Attestation Gatekeeper API.
 * 
 * Called by GetSwish AB's certificate issuance infrastructure
 * (hsm) to execute Steps 2, 5, and 7
 * of the gatekeeper verification flow.
 * 
 * Flow:
 *   TL submits CSR + attestation → GetSwish AB → this client → EBA/NCA gatekeeper
 *   
 *   Step 2: requestVerification()  → sends attestation evidence to gatekeeper
 *   Step 5: (response)             → receives signed verification receipt
 *   Step 6: (GetSwish AB decides)  → issues or refuses certificate
 *   Step 7: confirmIssuance()      → sends full certificate or non-issuance notice
 */
@Component
public class GatekeeperClient {

    private static final Logger log = LoggerFactory.getLogger(GatekeeperClient.class);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String gatekeeperBaseUrl;
    private final String countryCode;

    public GatekeeperClient(
            @Value("${gatekeeper.base-url:https://dora-api.eba.europa.eu}") String gatekeeperBaseUrl,
            @Value("${gatekeeper.country-code:SE}") String countryCode) {
        this.gatekeeperBaseUrl = gatekeeperBaseUrl;
        this.countryCode = countryCode;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.objectMapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    // =========================================================================
    // Step 2 → Step 5: Request verification, receive signed receipt
    // =========================================================================

    /**
     * Sends attestation evidence to the gatekeeper for verification (Step 2).
     * Returns the signed verification receipt (Step 5).
     * 
     * @param publicKeyPem       PEM-encoded public key from the CSR
     * @param hsmVendor          HSM vendor: SECUROSYS, YUBICO, AZURE, GOOGLE
     * @param attestationData    Vendor-specific attestation data (base64)
     * @param attestationSig     Attestation signature (Securosys only, nullable)
     * @param attestationChain   Attestation certificate chain (PEM strings)
     * @param supplierIdentifier Organisation number of the technical supplier
     * @param supplierName       Name of the technical supplier
     * @param keyPurpose         Purpose description, e.g. "Swish payment signing"
     * @return Signed verification receipt from the gatekeeper
     */
    public VerificationReceipt requestVerification(
            String publicKeyPem,
            String hsmVendor,
            String attestationData,
            String attestationSig,
            List<String> attestationChain,
            String supplierIdentifier,
            String supplierName,
            String keyPurpose) throws GatekeeperException {

        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("publicKey", publicKeyPem);
        body.put("hsmVendor", hsmVendor);
        if (attestationData != null) body.put("attestationData", attestationData);
        if (attestationSig != null) body.put("attestationSignature", attestationSig);
        body.put("attestationCertChain", attestationChain);
        body.put("supplierIdentifier", supplierIdentifier);
        body.put("supplierName", supplierName);
        body.put("keyPurpose", keyPurpose);

        String url = gatekeeperBaseUrl + "/v1/attestation/" + countryCode.toLowerCase() + "/verify";
        log.info("Step 2: Sending attestation evidence to gatekeeper: {}", url);

        try {
            String json = objectMapper.writeValueAsString(body);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .timeout(Duration.ofSeconds(30))
                    .build();

            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new GatekeeperException("Gatekeeper returned HTTP " + response.statusCode()
                        + ": " + response.body());
            }

            VerificationReceipt receipt = objectMapper.readValue(
                    response.body(), VerificationReceipt.class);

            log.info("Step 5: Received verification receipt. ID={}, compliant={}",
                    receipt.verificationId, receipt.compliant);

            return receipt;

        } catch (GatekeeperException e) {
            throw e;
        } catch (Exception e) {
            throw new GatekeeperException("Failed to communicate with gatekeeper: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // Step 7: Confirm issuance or non-issuance
    // =========================================================================

    /**
     * Sends issuance confirmation to the gatekeeper (Step 7).
     * If the certificate was issued, sends the full signing certificate
     * so EBA can independently verify the public key match.
     * 
     * @param verificationId      The verification ID from the Step 5 receipt
     * @param issued              Whether the certificate was issued
     * @param signingCertPem      Full signing certificate in PEM (null if not issued)
     * @param swishNumber         The Swish number associated with this certificate
     * @param organisationNumber  Organisation number of the corporate customer
     * @param nonIssuanceReason   Reason for non-issuance (null if issued)
     * @return Confirmation response from the gatekeeper
     */
    public ConfirmationResult confirmIssuance(
            String verificationId,
            boolean issued,
            String signingCertPem,
            String swishNumber,
            String organisationNumber,
            String nonIssuanceReason) throws GatekeeperException {

        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("verificationId", verificationId);
        body.put("issued", issued);
        body.put("timestamp", Instant.now().toString());
        body.put("swishNumber", swishNumber);
        body.put("organisationNumber", organisationNumber);
        if (issued && signingCertPem != null) {
            body.put("signingCertificatePem", signingCertPem);
        }
        if (!issued && nonIssuanceReason != null) {
            body.put("nonIssuanceReason", nonIssuanceReason);
        }

        String url = gatekeeperBaseUrl + "/v1/attestation/" + countryCode.toLowerCase() + "/confirm";
        log.info("Step 7: Sending issuance confirmation to gatekeeper. ID={}, issued={}",
                verificationId, issued);

        try {
            String json = objectMapper.writeValueAsString(body);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .timeout(Duration.ofSeconds(30))
                    .build();

            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new GatekeeperException("Gatekeeper returned HTTP " + response.statusCode()
                        + ": " + response.body());
            }

            ConfirmationResult result = objectMapper.readValue(
                    response.body(), ConfirmationResult.class);

            log.info("Step 7: Loop closed. Status={}, anomalies={}",
                    result.registryStatus, result.anomalies != null ? result.anomalies.size() : 0);

            return result;

        } catch (GatekeeperException e) {
            throw e;
        } catch (Exception e) {
            throw new GatekeeperException("Failed to send confirmation to gatekeeper: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // Response models
    // =========================================================================

    public static class VerificationReceipt {
        public String verificationId;
        public boolean compliant;
        public String verificationTimestamp;
        public String signature;
        public String signingCertificate;
        public String publicKeyFingerprint;
        public String publicKeyAlgorithm;
        public String hsmVendor;
        public String hsmModel;
        public String hsmSerialNumber;
        public Map<String, Object> keyProperties;
        public Map<String, Object> doraCompliance;
        public String supplierIdentifier;
        public String supplierName;
        public String countryCode;
        public List<String> errors;
        public List<String> warnings;
    }

    public static class ConfirmationResult {
        public String verificationId;
        public boolean loopClosed;
        public Boolean publicKeyMatch;
        public String expectedPublicKeyFingerprint;
        public String actualPublicKeyFingerprint;
        public String registryStatus;
        public String processedTimestamp;
        public List<String> anomalies;
    }

    public static class GatekeeperException extends Exception {
        public GatekeeperException(String message) { super(message); }
        public GatekeeperException(String message, Throwable cause) { super(message, cause); }
    }
}