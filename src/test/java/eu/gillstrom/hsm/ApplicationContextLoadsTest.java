package eu.gillstrom.hsm;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Loads the full Spring application context.
 *
 * <p>Every other test in this repository constructs its collaborators directly,
 * so a wiring defect — a missing bean, an ambiguous
 * {@code @ConditionalOnProperty} selection, a constructor that throws because a
 * pinned trust anchor no longer parses — would not surface until the
 * application was started. This test is the cheapest possible guard against
 * that class of failure: it asserts nothing about behaviour, only that the
 * context comes up.</p>
 *
 * <p>The properties below select the in-process mock gatekeeper and mock
 * issuance client that {@code application.yaml} already documents, so no
 * external gatekeeper, CA or network is required. {@code fail-closed} would
 * also load, but {@code mock} additionally exercises the {@code @PostConstruct}
 * key-generation and registry-registration paths.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(properties = {
        "swish.gatekeeper.mode=mock",
        "swish.issuance.mode=mock",
        "swish.signatory-rights.mode=fail-closed"
})
class ApplicationContextLoadsTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void contextLoads() {
        assertThat(context).isNotNull();
        assertThat(context.getBean(eu.gillstrom.hsm.service.AttestationService.class)).isNotNull();
    }
}
