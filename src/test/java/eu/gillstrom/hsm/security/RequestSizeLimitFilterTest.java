package eu.gillstrom.hsm.security;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestSizeLimitFilterTest {

    @Test
    void aDeclaredLengthAboveTheCapIs413BeforeTheBodyIsRead() throws Exception {
        RequestSizeLimitFilter filter = new RequestSizeLimitFilter("16B");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/attestation/verifyAndIssue");
        request.setContent(new byte[17]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(chain.getRequest()).as("the chain is not entered").isNull();
    }

    @Test
    void aDeclaredLengthAtTheCapPasses() throws Exception {
        RequestSizeLimitFilter filter = new RequestSizeLimitFilter("16B");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/attestation/verifyAndIssue");
        request.setContent(new byte[16]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(chain.getRequest()).isSameAs(request);
    }

    @Test
    void anUndeclaredLengthIsCountedWhileRead() throws Exception {
        RequestSizeLimitFilter filter = new RequestSizeLimitFilter("16B");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/attestation/verifyAndIssue") {
            @Override
            public long getContentLengthLong() {
                return -1;
            }

            @Override
            public int getContentLength() {
                return -1;
            }
        };
        request.setContent(new byte[17]);
        AtomicReference<HttpServletRequest> seen = new AtomicReference<>();
        filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> seen.set((HttpServletRequest) req));

        var in = seen.get().getInputStream();
        assertThat(in.readNBytes(16)).hasSize(16);
        assertThatThrownBy(in::read).isInstanceOf(IOException.class);

        MockHttpServletRequest small = new MockHttpServletRequest("POST", "/x") {
            @Override
            public long getContentLengthLong() {
                return -1;
            }
        };
        small.setContent(new byte[16]);
        filter.doFilter(small, new MockHttpServletResponse(), (req, res) -> seen.set((HttpServletRequest) req));
        assertThat(seen.get().getInputStream().readAllBytes()).hasSize(16);
        assertThat(seen.get().getReader()).isNotNull();
    }

    @Test
    void aNonPositiveCapIsRefused() {
        assertThatThrownBy(() -> new RequestSizeLimitFilter("0B")).isInstanceOf(IllegalArgumentException.class);
    }
}
