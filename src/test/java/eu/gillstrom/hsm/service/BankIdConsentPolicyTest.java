package eu.gillstrom.hsm.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BankIdConsentPolicyTest {

    private static final String ORG = "5569743098";
    private static final String SWISH = "1231015932";
    private static final String TL = "5569641234";
    private static final String MANDATE = "Bolagsnamn AB (556974-3098) ger härmed Teknisk leverantör AB "
            + "(556964-1234) fullmakt att hämta fyra (4) Swish-certifikat för Swish-nummer 1231015932 "
            + "kopplat till TL-nummer 9876543210.";

    private final BankIdConsentPolicy policy = new BankIdConsentPolicy(TL);

    @Test
    @DisplayName("A mandate naming the organisation and Swish number, from an allowed relying party, passes")
    void mandateFromAllowedRelyingPartyPasses() {
        assertThat(policy.violations(TL, MANDATE, ORG, SWISH, 4)).isEmpty();
    }

    @Test
    @DisplayName("The relying party may be given with a hyphen")
    void relyingPartyWithHyphenPasses() {
        assertThat(policy.violations("556964-1234", MANDATE, ORG, SWISH, 4)).isEmpty();
    }

    @Test
    @DisplayName("A 12-digit organisation number matches its 10-digit form in the text")
    void twelveDigitOrganisationNumberMatches() {
        assertThat(policy.violations(TL, MANDATE, "16" + ORG, SWISH, 4)).isEmpty();
    }

    @Test
    @DisplayName("A relying party not on the list is refused")
    void foreignRelyingPartyIsRefused() {
        assertThat(policy.violations("5566778899", MANDATE, ORG, SWISH, 4))
                .anyMatch(v -> v.startsWith("BANKID_RELYING_PARTY_NOT_ALLOWED"));
    }

    @Test
    @DisplayName("A missing relying party is refused")
    void missingRelyingPartyIsRefused() {
        assertThat(policy.violations(null, MANDATE, ORG, SWISH, 4))
                .anyMatch(v -> v.startsWith("BANKID_RELYING_PARTY_NOT_ALLOWED"));
    }

    @Test
    @DisplayName("An empty allow-list refuses every relying party")
    void emptyAllowListRefusesAll() {
        assertThat(new BankIdConsentPolicy("").violations(TL, MANDATE, ORG, SWISH, 4))
                .anyMatch(v -> v.startsWith("BANKID_RELYING_PARTY_NOT_ALLOWED"));
    }

    @Test
    @DisplayName("A harmless text without the request's numbers is refused")
    void harmlessTextIsRefused() {
        assertThat(policy.violations(TL, "Logga in hos Teknisk leverantör AB", ORG, SWISH, 4))
                .filteredOn(v -> v.startsWith("BANKID_VISIBLE_TEXT_MISMATCH"))
                .hasSize(3);
    }

    @Test
    @DisplayName("A text naming another organisation or Swish number is refused")
    void otherNumbersAreRefused() {
        assertThat(policy.violations(TL, MANDATE, "5569743099", SWISH, 4))
                .anyMatch(v -> v.contains("organisation number"));
        assertThat(policy.violations(TL, MANDATE, ORG, "1231015933", 4))
                .anyMatch(v -> v.contains("Swish number"));
    }

    @Test
    @DisplayName("A number embedded in a longer digit run does not count")
    void embeddedNumberDoesNotCount() {
        String text = "Avtal 155697430981 och 91231015932";

        assertThat(policy.violations(TL, text, ORG, SWISH, 0))
                .filteredOn(v -> v.startsWith("BANKID_VISIBLE_TEXT_MISMATCH"))
                .hasSize(2);
    }

    @Test
    @DisplayName("The visible text must state the mandate's count in parentheses")
    void theCountMustBeStated() {
        assertThat(policy.violations(TL, MANDATE, ORG, SWISH, 4)).isEmpty();
        assertThat(policy.violations(TL, MANDATE.replace("(4)", "( 4 )"), ORG, SWISH, 4)).isEmpty();
        assertThat(policy.violations(TL, MANDATE, ORG, SWISH, 5))
                .singleElement().asString().startsWith("BANKID_VISIBLE_TEXT_MISMATCH").contains("(5)");
        assertThat(policy.violations(TL, MANDATE.replace(" (4)", ""), ORG, SWISH, 4))
                .singleElement().asString().contains("number of certificates");
        // "fyra" alone, or 4 without parentheses, does not state the count.
        assertThat(policy.violations(TL, MANDATE.replace("(4)", "4"), ORG, SWISH, 4)).hasSize(1);
        // A one-certificate mandate must say so too.
        assertThat(policy.violations(TL, MANDATE, ORG, SWISH, 1))
                .singleElement().asString().contains("(1)");
        // A parenthesised number that merely contains the count is not it.
        assertThat(policy.violations(TL, MANDATE.replace("(4)", "(14)"), ORG, SWISH, 4)).hasSize(1);
    }
}
