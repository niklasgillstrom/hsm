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
        assertThat(policy.violations(TL, MANDATE, ORG, SWISH)).isEmpty();
    }

    @Test
    @DisplayName("The relying party may be given with a hyphen")
    void relyingPartyWithHyphenPasses() {
        assertThat(policy.violations("556964-1234", MANDATE, ORG, SWISH)).isEmpty();
    }

    @Test
    @DisplayName("A 12-digit organisation number matches its 10-digit form in the text")
    void twelveDigitOrganisationNumberMatches() {
        assertThat(policy.violations(TL, MANDATE, "16" + ORG, SWISH)).isEmpty();
    }

    @Test
    @DisplayName("A relying party not on the list is refused")
    void foreignRelyingPartyIsRefused() {
        assertThat(policy.violations("5566778899", MANDATE, ORG, SWISH))
                .anyMatch(v -> v.startsWith("BANKID_RELYING_PARTY_NOT_ALLOWED"));
    }

    @Test
    @DisplayName("A missing relying party is refused")
    void missingRelyingPartyIsRefused() {
        assertThat(policy.violations(null, MANDATE, ORG, SWISH))
                .anyMatch(v -> v.startsWith("BANKID_RELYING_PARTY_NOT_ALLOWED"));
    }

    @Test
    @DisplayName("An empty allow-list refuses every relying party")
    void emptyAllowListRefusesAll() {
        assertThat(new BankIdConsentPolicy("").violations(TL, MANDATE, ORG, SWISH))
                .anyMatch(v -> v.startsWith("BANKID_RELYING_PARTY_NOT_ALLOWED"));
    }

    @Test
    @DisplayName("A harmless text without the request's numbers is refused")
    void harmlessTextIsRefused() {
        assertThat(policy.violations(TL, "Logga in hos Teknisk leverantör AB", ORG, SWISH))
                .filteredOn(v -> v.startsWith("BANKID_VISIBLE_TEXT_MISMATCH"))
                .hasSize(2);
    }

    @Test
    @DisplayName("A text naming another organisation or Swish number is refused")
    void otherNumbersAreRefused() {
        assertThat(policy.violations(TL, MANDATE, "5569743099", SWISH))
                .anyMatch(v -> v.contains("organisation number"));
        assertThat(policy.violations(TL, MANDATE, ORG, "1231015933"))
                .anyMatch(v -> v.contains("Swish number"));
    }

    @Test
    @DisplayName("A number embedded in a longer digit run does not count")
    void embeddedNumberDoesNotCount() {
        String text = "Avtal 155697430981 och 91231015932";

        assertThat(policy.violations(TL, text, ORG, SWISH))
                .filteredOn(v -> v.startsWith("BANKID_VISIBLE_TEXT_MISMATCH"))
                .hasSize(2);
    }
}
