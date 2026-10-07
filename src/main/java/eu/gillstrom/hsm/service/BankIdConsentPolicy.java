package eu.gillstrom.hsm.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * What the BankID signatory must have seen, and who must have asked.
 *
 * <p>The request binding in {@code usrNonVisibleData} proves that the
 * signature belongs to this request, but the signatory never sees that string.
 * Without the two checks here, any company with its own BankID agreement could
 * have a signatory approve a harmless text with the binding hidden in the
 * non-visible data, and the signature would authorise a certificate.</p>
 *
 * <ol>
 *   <li><b>Relying party.</b> The organisation number of the BankID relying
 *       party ({@code srvInfo} in the signed data, i.e. the party whose BankID
 *       agreement started the order) must be in
 *       {@code swish.bankid.allowed-relying-parties}. Empty by default, which
 *       refuses every request until the operator names the technical suppliers
 *       it accepts.</li>
 *   <li><b>Visible text.</b> {@code usrVisibleData} must contain the request's
 *       organisation number and Swish number, so the signatory has seen which
 *       organisation and which Swish number the authorisation covers. The
 *       wording is otherwise free; an organisation number may be written with
 *       a hyphen (556954-1234). It must also state the number of certificates
 *       the mandate in the non-visible data authorises, in parentheses, as in
 *       "fyra (4) Swish-certifikat", so the signatory has seen how many
 *       certificates the signature can obtain.</li>
 * </ol>
 */
@Component
public class BankIdConsentPolicy {

    private static final Logger log = LoggerFactory.getLogger(BankIdConsentPolicy.class);

    /** A hyphen or space between two digits, as in "556954-1234". */
    private static final Pattern DIGIT_SEPARATOR = Pattern.compile("(?<=\\d)[\\s-](?=\\d)");

    private final Set<String> allowedRelyingParties;

    public BankIdConsentPolicy(
            @Value("${swish.bankid.allowed-relying-parties:}") String allowedRelyingParties) {
        this.allowedRelyingParties = Arrays.stream(
                        allowedRelyingParties == null ? new String[0] : allowedRelyingParties.split(","))
                .map(BankIdConsentPolicy::digits)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
        if (this.allowedRelyingParties.isEmpty()) {
            log.warn("BankIdConsentPolicy: swish.bankid.allowed-relying-parties is empty. Every request "
                    + "will be refused until the accepted BankID relying parties are configured.");
        }
    }

    /** @return the violations, empty if the signature satisfies both checks */
    public List<String> violations(String relyingPartyOrgNumber, String usrVisibleData,
            String organisationNumber, String swishNumber, int mandateCount) {
        List<String> out = new ArrayList<>();
        String rp = digits(relyingPartyOrgNumber);
        if (rp.isEmpty() || !allowedRelyingParties.contains(rp)) {
            out.add("BANKID_RELYING_PARTY_NOT_ALLOWED: the BankID order was started by relying party "
                    + (rp.isEmpty() ? "<none>" : rp)
                    + ", which is not in swish.bankid.allowed-relying-parties");
        }
        String text = usrVisibleData == null ? "" : DIGIT_SEPARATOR.matcher(usrVisibleData).replaceAll("");
        if (!containsOrganisationNumber(text, digits(organisationNumber))) {
            out.add("BANKID_VISIBLE_TEXT_MISMATCH: the text the signatory approved does not contain "
                    + "the organisation number of this request");
        }
        if (!containsNumber(text, digits(swishNumber))) {
            out.add("BANKID_VISIBLE_TEXT_MISMATCH: the text the signatory approved does not contain "
                    + "the Swish number of this request");
        }
        if (mandateCount > 0 && !Pattern.compile("\\(\\s*" + mandateCount + "\\s*\\)").matcher(text).find()) {
            out.add("BANKID_VISIBLE_TEXT_MISMATCH: the text the signatory approved does not state "
                    + "the number of certificates in the mandate, as (" + mandateCount + ")");
        }
        return out;
    }

    private static boolean containsOrganisationNumber(String text, String org) {
        if (containsNumber(text, org)) {
            return true;
        }
        // A 12-digit form ("16" + the 10 digits) is commonly written as 10 digits.
        return org.length() == 12 && org.startsWith("16") && containsNumber(text, org.substring(2));
    }

    /** Whole-number match: {@code number} not preceded or followed by another digit. */
    private static boolean containsNumber(String text, String number) {
        if (number.isEmpty()) {
            return false;
        }
        return Pattern.compile("(?<!\\d)" + Pattern.quote(number) + "(?!\\d)").matcher(text).find();
    }

    private static String digits(String s) {
        return s == null ? "" : s.replaceAll("\\D", "");
    }
}
