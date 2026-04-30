package eu.gillstrom.hsm.gatekeeper;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Production-shaped {@link GatekeeperClient} that POSTs JSON to the
 * configured gatekeeper. Selected via {@code swish.gatekeeper.mode=http}.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code POST {url}/v1/attestation/{countryCode}/verify} — body
 *       {@link VerifyRequest}, response {@link VerifyResponse}</li>
 *   <li>{@code POST {url}/v1/attestation/{countryCode}/confirm} — body
 *       {@link IssuanceConfirmRequest}, response
 *       {@link IssuanceConfirmResponse}</li>
 * </ul>
 *
 * <p>The base URL configured via {@code swish.gatekeeper.url} is the
 * gatekeeper's host root (e.g. {@code https://dora-api.eba.europa.eu}) — the
 * {@code /v1/attestation/{countryCode}/...} suffix is appended by this
 * client. Country code defaults to {@code SE} via
 * {@code swish.gatekeeper.country-code}.
 *
 * <p>This client does NOT verify the receipt signature itself; that is the
 * caller's responsibility, see {@link ReceiptVerifier}. It only handles
 * transport and JSON marshalling.
 */
@Component
@ConditionalOnProperty(name = "swish.gatekeeper.mode", havingValue = "http")
public class HttpGatekeeperClient implements GatekeeperClient {

    private static final Logger log = LoggerFactory.getLogger(HttpGatekeeperClient.class);

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private final HttpClient http;
    private final URI base;
    private final String countryCode;
    private final Duration timeout;

    public HttpGatekeeperClient(
            @Value("${swish.gatekeeper.url}") String url,
            @Value("${swish.gatekeeper.country-code:SE}") String countryCode,
            @Value("${swish.gatekeeper.timeout-ms:5000}") long timeoutMs) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException(
                    "swish.gatekeeper.url must be set when swish.gatekeeper.mode=http");
        }
        if (countryCode == null || countryCode.isBlank()) {
            throw new IllegalArgumentException(
                    "swish.gatekeeper.country-code must be a non-blank ISO 3166-1 alpha-2 code");
        }
        this.base = URI.create(stripTrailingSlash(url));
        this.countryCode = countryCode;
        this.timeout = Duration.ofMillis(timeoutMs);
        this.http = HttpClient.newBuilder().connectTimeout(this.timeout).build();
        log.info("HttpGatekeeperClient configured: base={} countryCode={} timeout={}ms",
                this.base, this.countryCode, timeoutMs);
    }

    @Override
    public VerifyResponse verify(VerifyRequest request) throws GatekeeperException {
        URI uri = base.resolve("/v1/attestation/" + countryCode + "/verify");
        try {
            String body = MAPPER.writeValueAsString(request);
            HttpRequest req = HttpRequest.newBuilder(uri)
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> resp = http.send(req,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() != 200) {
                throw new GatekeeperException(
                        "Gatekeeper verify returned HTTP " + resp.statusCode() + ": " + resp.body());
            }
            return MAPPER.readValue(resp.body(), VerifyResponse.class);
        } catch (GatekeeperException e) {
            throw e;
        } catch (Exception e) {
            throw new GatekeeperException(
                    "Gatekeeper verify call failed: " + e.getMessage(), e);
        }
    }

    @Override
    public IssuanceConfirmResponse confirm(IssuanceConfirmRequest request) throws GatekeeperException {
        URI uri = base.resolve("/v1/attestation/" + countryCode + "/confirm");
        try {
            String body = MAPPER.writeValueAsString(request);
            HttpRequest req = HttpRequest.newBuilder(uri)
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> resp = http.send(req,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() != 200) {
                throw new GatekeeperException(
                        "Gatekeeper confirm returned HTTP " + resp.statusCode() + ": " + resp.body());
            }
            return MAPPER.readValue(resp.body(), IssuanceConfirmResponse.class);
        } catch (GatekeeperException e) {
            throw e;
        } catch (Exception e) {
            throw new GatekeeperException(
                    "Gatekeeper confirm call failed: " + e.getMessage(), e);
        }
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
