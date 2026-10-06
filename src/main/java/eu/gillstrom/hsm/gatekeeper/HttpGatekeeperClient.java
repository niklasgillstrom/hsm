package eu.gillstrom.hsm.gatekeeper;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundles;
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

    static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private final HttpClient http;
    private final URI base;
    private final String countryCode;
    private final Duration timeout;

    /** Bound on the response body quoted in an error message. */
    static final int MAX_QUOTED_BODY = 512;

    @Autowired
    public HttpGatekeeperClient(
            @Value("${swish.gatekeeper.url}") String url,
            @Value("${swish.gatekeeper.country-code:SE}") String countryCode,
            @Value("${swish.gatekeeper.timeout-ms:5000}") long timeoutMs,
            @Value("${swish.gatekeeper.allow-insecure-http:false}") boolean allowInsecureHttp,
            @Value("${swish.gatekeeper.ssl-bundle:}") String sslBundle,
            ObjectProvider<SslBundles> sslBundles) {
        this(url, countryCode, timeoutMs, allowInsecureHttp, sslBundle, sslBundles.getIfAvailable());
    }

    /**
     * @param allowInsecureHttp accept an {@code http://} URL (local
     *     development only): the verify request carries the attestation and
     *     the organisation number, and both calls carry the confirmation
     *     nonce, which over plain HTTP anyone on the path can read
     * @param sslBundle name of the Spring Boot SSL bundle with the trust
     *     store for the gatekeeper's certificate and the key store for the
     *     FE's client certificate (mTLS); blank uses the JVM defaults
     */
    HttpGatekeeperClient(String url, String countryCode, long timeoutMs, boolean allowInsecureHttp,
            String sslBundle, SslBundles sslBundles) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException(
                    "swish.gatekeeper.url must be set when swish.gatekeeper.mode=http");
        }
        if (!url.trim().toLowerCase(java.util.Locale.ROOT).startsWith("https://")) {
            if (!allowInsecureHttp) {
                throw new IllegalArgumentException("swish.gatekeeper.url must use https:// (configured: '"
                        + url + "'). Set swish.gatekeeper.allow-insecure-http=true for a local "
                        + "development run only.");
            }
            log.warn("swish.gatekeeper.url is '{}' and swish.gatekeeper.allow-insecure-http=true: "
                    + "gatekeeper traffic is unencrypted. This configuration MUST NOT be deployed.", url);
        }
        if (countryCode == null || countryCode.isBlank()) {
            throw new IllegalArgumentException(
                    "swish.gatekeeper.country-code must be a non-blank ISO 3166-1 alpha-2 code");
        }
        this.base = URI.create(stripTrailingSlash(url.trim()));
        this.countryCode = countryCode;
        this.timeout = Duration.ofMillis(timeoutMs);
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(this.timeout)
                .followRedirects(HttpClient.Redirect.NEVER);
        if (sslBundle != null && !sslBundle.isBlank()) {
            if (sslBundles == null) {
                throw new IllegalStateException("swish.gatekeeper.ssl-bundle is '" + sslBundle
                        + "' but no SSL bundle registry is available");
            }
            builder.sslContext(sslBundles.getBundle(sslBundle.trim()).createSslContext());
        }
        this.http = builder.build();
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
                        "Gatekeeper verify returned HTTP " + resp.statusCode() + ": " + quoted(resp.body()));
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
                        "Gatekeeper confirm returned HTTP " + resp.statusCode() + ": " + quoted(resp.body()));
            }
            return MAPPER.readValue(resp.body(), IssuanceConfirmResponse.class);
        } catch (GatekeeperException e) {
            throw e;
        } catch (Exception e) {
            throw new GatekeeperException(
                    "Gatekeeper confirm call failed: " + e.getMessage(), e);
        }
    }

    /** For tests. */
    HttpClient httpClient() {
        return http;
    }

    /** The start of a response body, without line breaks, for an error message. */
    static String quoted(String body) {
        if (body == null) {
            return "";
        }
        String flat = body.replaceAll("[\\r\\n]+", " ");
        return flat.length() <= MAX_QUOTED_BODY ? flat : flat.substring(0, MAX_QUOTED_BODY) + "…";
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
