package eu.gillstrom.hsm.service;

import eu.gillstrom.hsm.testsupport.TestPki;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The caller's transport certificate must be the company's own or its technical supplier's. */
class CallerPolicyTest {

    private static final String ORG = "5569743098";
    private static final String SWISH = "1231015932";
    private static final String SUPPLIER_ORG = "5566778899";

    private final CallerPolicy policy = new CallerPolicy("required");

    @Test
    void theCompanysOwnTransportCertificateIsAccepted() throws Exception {
        X509Certificate caller = TestPki.withSubject("C=SE, O=5569743098, CN=1231015932");

        assertThat(policy.violations(caller, ORG, SWISH, SUPPLIER_ORG)).isEmpty();
        // Organisation and Swish numbers written with separators or the 16 prefix are the same numbers.
        assertThat(policy.violations(caller, "16556974-3098", "123 101 59 32", SUPPLIER_ORG)).isEmpty();
    }

    @Test
    void aCompanyCertificateCannotRequestForAnotherSwishNumber() throws Exception {
        X509Certificate caller = TestPki.withSubject("C=SE, O=5569743098, CN=1231015932");

        assertThat(policy.violations(caller, ORG, "1239999999", SUPPLIER_ORG))
                .singleElement().asString().startsWith("CALLER_NOT_BOUND");
    }

    @Test
    void aCompanyCertificateCannotRequestForAnotherOrganisation() throws Exception {
        X509Certificate caller = TestPki.withSubject("C=SE, O=5561234567, CN=1231015932");

        assertThat(policy.violations(caller, ORG, SWISH, SUPPLIER_ORG))
                .singleElement().asString().startsWith("CALLER_NOT_BOUND");
    }

    @Test
    void theRelyingPartysSupplierCertificateIsAccepted() throws Exception {
        X509Certificate caller = TestPki.withSubject("C=SE, O=5566778899, CN=9871234567");

        assertThat(policy.violations(caller, ORG, SWISH, SUPPLIER_ORG)).isEmpty();
        assertThat(policy.violations(caller, ORG, SWISH, "16" + SUPPLIER_ORG)).isEmpty();
    }

    @Test
    void aSupplierThatIsNotTheRelyingPartyIsRefused() throws Exception {
        X509Certificate caller = TestPki.withSubject("C=SE, O=5561112223, CN=9871234567");

        assertThat(policy.violations(caller, ORG, SWISH, SUPPLIER_ORG))
                .singleElement().asString().startsWith("CALLER_NOT_BOUND");
        // An invalid BankID result carries no relying party.
        X509Certificate supplier = TestPki.withSubject("C=SE, O=5566778899, CN=9871234567");
        assertThat(policy.violations(supplier, ORG, SWISH, null))
                .singleElement().asString().startsWith("CALLER_NOT_BOUND");
    }

    @Test
    void aMissingCertificateIsRefused() {
        assertThat(policy.violations(null, ORG, SWISH, SUPPLIER_ORG))
                .singleElement().asString().startsWith("CALLER_CERTIFICATE_MISSING");
    }

    @Test
    void anyOtherNumberIsRefused() throws Exception {
        X509Certificate caller = TestPki.withSubject("C=SE, O=5569743098, CN=4561015932");

        assertThat(policy.violations(caller, ORG, SWISH, ORG))
                .singleElement().asString().contains("neither a Swish number");
        // Close to the two series, but in neither.
        X509Certificate near123 = TestPki.withSubject("C=SE, O=5569743098, CN=1291015932");
        assertThat(policy.violations(near123, ORG, "1291015932", ORG))
                .singleElement().asString().contains("neither a Swish number");
        X509Certificate near987 = TestPki.withSubject("C=SE, O=5566778899, CN=9811234567");
        assertThat(policy.violations(near987, ORG, SWISH, SUPPLIER_ORG))
                .singleElement().asString().contains("neither a Swish number");
    }

    @Test
    void onlyTheSixteenPrefixOfATwelveDigitNumberIsDropped() throws Exception {
        X509Certificate caller = TestPki.withSubject("C=SE, O=5569743098, CN=1231015932");
        // Twelve digits with another prefix are not the ten-digit number.
        assertThat(policy.violations(caller, "995569743098", SWISH, SUPPLIER_ORG))
                .singleElement().asString().startsWith("CALLER_NOT_BOUND");
        // A ten-digit number that starts with 16 keeps its digits.
        X509Certificate supplier = TestPki.withSubject("C=SE, O=1612345678, CN=9871234567");
        assertThat(policy.violations(supplier, ORG, SWISH, "12345678"))
                .singleElement().asString().startsWith("CALLER_NOT_BOUND");
    }

    @Test
    void aSubjectWithoutExactlyOneCnAndOIsRefused() throws Exception {
        for (String dn : new String[] {
                "C=SE, CN=1231015932",
                "C=SE, O=5569743098",
                "C=SE, O=5569743098, CN=1231015932, CN=1231015932",
                "C=SE, O=5569743098, O=5569743098, CN=1231015932",
                "C=SE, O=Testbolaget AB, CN=1231015932"}) {
            assertThat(policy.violations(TestPki.withSubject(dn), ORG, SWISH, SUPPLIER_ORG))
                    .as(dn).singleElement().asString().contains("no single CN and O");
        }
        // CN in a multi-valued RDN.
        X500Name multi = new X500Name(new RDN[] {
                new RDN(new AttributeTypeAndValue(BCStyle.O, new DERUTF8String(ORG))),
                new RDN(new AttributeTypeAndValue[] {
                        new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(SWISH)),
                        new AttributeTypeAndValue(BCStyle.SERIALNUMBER, new DERUTF8String("1"))})});
        assertThat(policy.violations(TestPki.withSubject(multi), ORG, SWISH, SUPPLIER_ORG))
                .singleElement().asString().contains("no single CN and O");
    }

    @Test
    void theCnMustBeTheNumberExactly() throws Exception {
        X500Name padded = new X500Name(new RDN[] {
                new RDN(new AttributeTypeAndValue(BCStyle.O, new DERUTF8String(ORG))),
                new RDN(new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(SWISH + " ")))});
        assertThat(policy.violations(TestPki.withSubject(padded), ORG, SWISH, SUPPLIER_ORG))
                .singleElement().asString().startsWith("CALLER_NOT_BOUND");
    }

    @Test
    void offAcceptsAnything() {
        assertThat(CallerPolicy.off().violations(null, ORG, SWISH, SUPPLIER_ORG)).isEmpty();
        assertThat(new CallerPolicy(" OFF ").violations(null, ORG, SWISH, SUPPLIER_ORG)).isEmpty();
        assertThat(new CallerPolicy(" Required ").violations(null, ORG, SWISH, SUPPLIER_ORG)).isNotEmpty();
    }

    @Test
    void anUnknownModeIsAConfigurationError() {
        assertThatThrownBy(() -> new CallerPolicy("lenient")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new CallerPolicy("")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new CallerPolicy(null)).isInstanceOf(IllegalStateException.class);
    }
}
