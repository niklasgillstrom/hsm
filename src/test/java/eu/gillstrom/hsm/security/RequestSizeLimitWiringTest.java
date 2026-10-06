package eu.gillstrom.hsm.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** The size limit applies to the running application's endpoints. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "swish.limits.max-http-request-size=4KB")
class RequestSizeLimitWiringTest {

    @LocalServerPort
    private int port;

    private int post(String body) throws Exception {
        HttpClient client = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port
                        + "/api/v1/attestation/verifyAndIssue"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    @Test
    void anOversizedRequestIs413AndASmallOneReachesTheController() throws Exception {
        assertThat(post("{\"csr\":\"" + "x".repeat(5000) + "\"}")).isEqualTo(413);
        assertThat(post("{}")).isEqualTo(400);
    }
}
