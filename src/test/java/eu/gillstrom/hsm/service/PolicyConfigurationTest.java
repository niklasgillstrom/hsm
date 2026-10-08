package eu.gillstrom.hsm.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.DefaultResourceLoader;

import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The start-up warnings for a configuration that refuses or accepts
 * everything, the wording of the relying-party refusal, and the refusals for
 * a missing Swish number and a missing personal number.
 */
class PolicyConfigurationTest {

    private static final String ORG = "5569743098";
    private static final String SWISH = "1231015932";
    private static final String TL = "5569641234";
    private static final String MANDATE = "Bolagsnamn AB (556974-3098) ger fullmakt att hämta fyra (4) "
            + "Swish-certifikat för Swish-nummer 1231015932.";

    private static List<String> warningsWhile(Class<?> type, Supplier<?> action) {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        Logger logger = (Logger) LoggerFactory.getLogger(type);
        logger.addAppender(appender);
        try {
            action.get();
        } finally {
            logger.detachAppender(appender);
        }
        return appender.list.stream()
                .filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    @Test
    void anEmptyRelyingPartyListIsWarnedAboutAndBlankEntriesDoNotCount() {
        assertThat(warningsWhile(BankIdConsentPolicy.class, () -> new BankIdConsentPolicy("")))
                .anyMatch(m -> m.contains("allowed-relying-parties is empty"));
        assertThat(warningsWhile(BankIdConsentPolicy.class, () -> new BankIdConsentPolicy(" , ,")))
                .anyMatch(m -> m.contains("allowed-relying-parties is empty"));
        assertThat(warningsWhile(BankIdConsentPolicy.class, () -> new BankIdConsentPolicy(TL))).isEmpty();
    }

    @Test
    void theRelyingPartyRefusalNamesTheRelyingPartyOrNone() {
        BankIdConsentPolicy policy = new BankIdConsentPolicy(TL);

        assertThat(policy.violations("5566778899", MANDATE, ORG, SWISH, 4))
                .anyMatch(v -> v.contains("started by relying party 5566778899,"));
        assertThat(policy.violations(null, MANDATE, ORG, SWISH, 4))
                .anyMatch(v -> v.contains("started by relying party <none>,"));
    }

    @Test
    void aMissingSwishNumberIsNeverFoundInTheText() {
        BankIdConsentPolicy policy = new BankIdConsentPolicy(TL);

        assertThat(policy.violations(TL, MANDATE, ORG, "", 4))
                .containsExactly("BANKID_VISIBLE_TEXT_MISMATCH: the text the signatory approved does not "
                        + "contain the Swish number of this request");
        assertThat(policy.violations(TL, MANDATE, ORG, null, 4)).hasSize(1);
    }

    @Test
    void callerBindingOffIsWarnedAboutAndRequiredIsNot() {
        assertThat(warningsWhile(CallerPolicy.class, () -> new CallerPolicy("off")))
                .anyMatch(m -> m.contains("MUST NOT be deployed"));
        assertThat(warningsWhile(CallerPolicy.class, () -> new CallerPolicy("required"))).isEmpty();
    }

    @Test
    void theMockRegistryRefusesAMissingPersonalOrOrganisationNumber() {
        MockAgreementRegistrySignatoryRightsVerifier verifier =
                new MockAgreementRegistrySignatoryRightsVerifier(new DefaultResourceLoader(), "file:/nonexistent");

        for (SignatoryRightsVerifier.Result r : List.of(
                verifier.check(null, ORG, SWISH), verifier.check("198001011234", null, SWISH))) {
            assertThat(r.status()).isEqualTo(SignatoryRightsVerifier.Result.Status.UNAUTHORISED);
            assertThat(r.reason()).isEqualTo("Missing personalNumber or organisationNumber");
        }
    }
}
