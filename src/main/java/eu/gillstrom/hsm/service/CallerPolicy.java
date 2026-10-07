package eu.gillstrom.hsm.service;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Binds the caller's transport certificate to the request.
 *
 * <p>In Swish the certificate API is called with mTLS, using either the
 * company's transport certificate (its Swish number, 123…) or the technical
 * supplier's (its number, 987…). Both carry the number in CN and the
 * organisation number in O, as in the reference requests in {@code examples/}
 * ({@code C=SE, O=5569743098, CN=1231015932}).</p>
 *
 * <ul>
 *   <li>A 123 certificate may only request certificates for itself: CN must be
 *       the request's Swish number and O its organisation number.</li>
 *   <li>A 987 certificate may request on behalf of its customers: O must be the
 *       BankID relying party, the technical supplier that started the BankID
 *       order the signatory approved.</li>
 *   <li>No certificate, or any other number, is refused.</li>
 * </ul>
 *
 * <p>The certificate itself, its chain to the Swish CA and its validity, is
 * checked by the TLS layer ({@code server.ssl.client-auth=need} with the Swish
 * CA in the trust store); this class reads the identity the handshake
 * established. {@code swish.caller-binding=off} switches the check off for a
 * local development run without mTLS; the {@code dev} profile sets it.</p>
 */
@Component
public class CallerPolicy {

    private static final Logger log = LoggerFactory.getLogger(CallerPolicy.class);

    private final boolean required;

    public CallerPolicy(@Value("${swish.caller-binding:required}") String mode) {
        String m = mode == null ? "" : mode.trim().toLowerCase(Locale.ROOT);
        if (!m.equals("required") && !m.equals("off")) {
            throw new IllegalStateException("swish.caller-binding must be 'required' or 'off', not '" + mode + "'");
        }
        this.required = m.equals("required");
        if (!required) {
            log.warn("swish.caller-binding=off: the caller's transport certificate is not compared with "
                    + "the request. This configuration MUST NOT be deployed.");
        }
    }

    /** For tests of everything else: the check switched off. */
    public static CallerPolicy off() {
        return new CallerPolicy("off");
    }

    /**
     * @param caller                the client certificate of the TLS connection, or null
     * @param relyingPartyOrgNumber the organisation number of the BankID relying party
     */
    public List<String> violations(X509Certificate caller, String organisationNumber, String swishNumber,
            String relyingPartyOrgNumber) {
        List<String> out = new ArrayList<>();
        if (!required) {
            return out;
        }
        if (caller == null) {
            out.add("CALLER_CERTIFICATE_MISSING: the request was not made with a transport certificate (mTLS)");
            return out;
        }
        String number = single(caller, BCStyle.CN);
        String org = digits(single(caller, BCStyle.O));
        if (number == null || org.isEmpty()) {
            out.add("CALLER_NOT_BOUND: the transport certificate's subject has no single CN and O");
            return out;
        }
        if (number.startsWith("123")) {
            if (!number.equals(digits(swishNumber)) || !sameOrganisation(org, digits(organisationNumber))) {
                out.add("CALLER_NOT_BOUND: transport certificate " + number
                        + " may only request certificates for its own Swish number and organisation");
            }
        } else if (number.startsWith("987")) {
            if (!sameOrganisation(org, digits(relyingPartyOrgNumber))) {
                out.add("CALLER_NOT_BOUND: technical supplier certificate " + number
                        + " is not the BankID relying party of this request");
            }
        } else {
            out.add("CALLER_NOT_BOUND: transport certificate " + number
                    + " is neither a Swish number (123) nor a technical supplier number (987)");
        }
        return out;
    }

    /** The value of the one {@code type} attribute in the subject, or null. */
    private static String single(X509Certificate cert, ASN1ObjectIdentifier type) {
        RDN[] rdns = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()).getRDNs(type);
        if (rdns.length != 1 || rdns[0].isMultiValued()) {
            return null;
        }
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

    /**
     * Organisation numbers compared on their ten digits ("16" + ten digits is
     * the same number), as in BankIdConsentPolicy. {@code a} is never empty.
     */
    private static boolean sameOrganisation(String a, String b) {
        return ten(a).equals(ten(b));
    }

    private static String ten(String digits) {
        return digits.length() == 12 && digits.startsWith("16") ? digits.substring(2) : digits;
    }

    private static String digits(String s) {
        return s == null ? "" : s.replaceAll("\\D", "");
    }
}
