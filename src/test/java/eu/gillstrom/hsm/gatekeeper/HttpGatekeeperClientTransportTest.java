package eu.gillstrom.hsm.gatekeeper;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HttpGatekeeperClientTransportTest {

    @Test
    void plainHttpIsRefusedUnlessExplicitlyAllowed() {
        assertThatThrownBy(() -> new HttpGatekeeperClient("http://gatekeeper.test", "SE", 1000, false, "", (SslBundles) null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("https://");
        assertThatCode(() -> new HttpGatekeeperClient("http://gatekeeper.test", "SE", 1000, true, "", (SslBundles) null))
                .doesNotThrowAnyException();
        assertThatCode(() -> new HttpGatekeeperClient(" HTTPS://gatekeeper.test", "SE", 1000, false, "", (SslBundles) null))
                .doesNotThrowAnyException();
    }

    @Test
    void theSslBundleProvidesTheTlsContext() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);
        SslBundle bundle = mock(SslBundle.class);
        when(bundle.createSslContext()).thenReturn(context);
        SslBundles bundles = mock(SslBundles.class);
        when(bundles.getBundle("gatekeeper")).thenReturn(bundle);

        HttpGatekeeperClient client = new HttpGatekeeperClient("https://gatekeeper.test", "SE", 1000, false,
                " gatekeeper ", bundles);
        assertThat(client.httpClient().sslContext()).isSameAs(context);

        HttpGatekeeperClient jvmDefault = new HttpGatekeeperClient("https://gatekeeper.test", "SE", 1000, false,
                "", bundles);
        assertThat(jvmDefault.httpClient().sslContext()).isNotSameAs(context);

        assertThatThrownBy(() -> new HttpGatekeeperClient("https://gatekeeper.test", "SE", 1000, false,
                "gatekeeper", (SslBundles) null)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void anErrorBodyIsQuotedShortAndOnOneLine() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] body = ("line one\r\nline two " + "x".repeat(5000)).getBytes(StandardCharsets.UTF_8);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(500, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            HttpGatekeeperClient client = new HttpGatekeeperClient(
                    "http://127.0.0.1:" + server.getAddress().getPort(), "SE", 5000, true, "", (SslBundles) null);
            assertThatThrownBy(() -> client.verify(VerifyRequest.builder().build()))
                    .isInstanceOf(GatekeeperException.class)
                    .hasMessageStartingWith("Gatekeeper verify returned HTTP 500: line one line two x")
                    .hasMessageNotContaining("\n")
                    .satisfies(e -> assertThat(e.getMessage()).hasSizeLessThan(600));
            assertThatThrownBy(() -> client.confirm(IssuanceConfirmRequest.builder().build()))
                    .hasMessageStartingWith("Gatekeeper confirm returned HTTP 500: line one line two x")
                    .satisfies(e -> assertThat(e.getMessage()).hasSizeLessThan(600));
        } finally {
            server.stop(0);
        }
        assertThat(HttpGatekeeperClient.quoted("a".repeat(HttpGatekeeperClient.MAX_QUOTED_BODY)))
                .hasSize(HttpGatekeeperClient.MAX_QUOTED_BODY);
        assertThat(HttpGatekeeperClient.quoted("a".repeat(HttpGatekeeperClient.MAX_QUOTED_BODY + 1)))
                .hasSize(HttpGatekeeperClient.MAX_QUOTED_BODY + 1).endsWith("…");
        assertThat(HttpGatekeeperClient.quoted(null)).isEmpty();
    }

    @Test
    void aSuccessfulAnswerIsReadIntoTheResponseAndTheCountryIsInThePath() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        java.util.List<String> paths = new java.util.concurrent.CopyOnWriteArrayList<>();
        server.createContext("/", exchange -> {
            paths.add(exchange.getRequestURI().getPath());
            byte[] body = "{\"verificationId\":\"v-1\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            // A trailing slash on the configured URL is accepted.
            HttpGatekeeperClient client = new HttpGatekeeperClient(
                    "http://127.0.0.1:" + server.getAddress().getPort() + "/", "SE", 5000, true, "",
                    (SslBundles) null);
            assertThat(client.verify(VerifyRequest.builder().build()).getVerificationId()).isEqualTo("v-1");
            assertThat(client.confirm(IssuanceConfirmRequest.builder().build()).getVerificationId())
                    .isEqualTo("v-1");
            assertThat(paths).containsExactly("/v1/attestation/SE/verify", "/v1/attestation/SE/confirm");
        } finally {
            server.stop(0);
        }
    }
}
