package eu.gillstrom.hsm.service;

import eu.gillstrom.hsm.testsupport.BankIdFixture;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.cert.ocsp.jcajce.JcaRespID;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The parts of BankID verification below {@link BankIdService#verify}: the
 * XML parser's refusals, the OCSP response shapes refused before any
 * signature check, a signatory certificate without a personal number, the
 * XML-DSig preconditions, Id registration, certificate extraction, the PKIX
 * path, and the text and DN helpers.
 */
class BankIdServiceInternalsTest {

    private static final String DSIG = "http://www.w3.org/2000/09/xmldsig#";

    private static BankIdFixture fx;
    private static BankIdService service;

    @BeforeAll
    static void setUp() throws Exception {
        fx = new BankIdFixture();
        service = new BankIdService(fx.anchors());
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newDefaultInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static Document parseBase64(String b64) throws Exception {
        return parse(new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8));
    }

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String certB64(X509Certificate c) throws Exception {
        return Base64.getEncoder().encodeToString(c.getEncoded());
    }

    // ---- XML parsing ------------------------------------------------------------------------

    @Test
    void aDoctypeIsRefused() {
        for (String xml : List.of(
                "<!DOCTYPE Signature SYSTEM \"http://127.0.0.1:1/attack.dtd\"><Signature/>",
                "<!DOCTYPE Signature [<!ENTITY % p SYSTEM \"file:///etc/hostname\"> %p;]><Signature/>")) {
            BankIdService.BankIdResult r = service.verify(b64(xml), "AA==");
            assertThat(r.isValid()).isFalse();
            assertThat(r.getError()).startsWith("Parse error").contains("DOCTYPE");
        }
    }

    @Test
    void anUndeclaredEntityIsRefused() {
        BankIdService.BankIdResult r = service.verify(b64("<Signature>&x;</Signature>"), "AA==");
        assertThat(r.getError()).startsWith("Parse error");
    }

    @Test
    void theParserAppliesTheJdksAttributeLimit() {
        StringBuilder attributes = new StringBuilder();
        for (int i = 0; i <= 10_000; i++) {
            attributes.append(" a").append(i).append("=\"x\"");
        }
        BankIdService.BankIdResult r = service.verify(b64("<Signature" + attributes + "/>"), "AA==");
        assertThat(r.getError()).startsWith("Parse error").contains("JAXP00010002");
    }

    // ---- OCSP shapes refused before the responder is examined -------------------------------

    private static String ocspError(byte[] ocsp) throws Exception {
        String signature = fx.signedResponseBase64("Text");
        BankIdService.BankIdResult r = service.verify(signature, Base64.getEncoder().encodeToString(ocsp));
        assertThat(r.isValid()).isFalse();
        return r.getError();
    }

    @Test
    void anUnsuccessfulOcspResponseIsRefused() throws Exception {
        byte[] ocsp = new OCSPRespBuilder().build(OCSPRespBuilder.TRY_LATER, null).getEncoded();
        assertThat(ocspError(ocsp)).isEqualTo("OCSP verification failed: OCSP responder returned status 3");
    }

    @Test
    void anOcspResponseOfAnotherTypeIsRefused() throws Exception {
        byte[] ocsp = new OCSPResp(new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL),
                new ResponseBytes(new ASN1ObjectIdentifier("1.2.3.4"), new DEROctetString(new byte[] {1}))))
                .getEncoded();
        assertThat(ocspError(ocsp)).isEqualTo("OCSP verification failed: OCSP response is not a BasicOCSPResp");
    }

    @Test
    void anOcspResponseWithoutAResponderCertificateIsRefused() throws Exception {
        CertificateID id = new JcaCertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                fx.bankCaCert, fx.personCert.getSerialNumber());
        BasicOCSPResp basic = new BasicOCSPRespBuilder(new JcaRespID(fx.ocspCert.getSubjectX500Principal()))
                .addResponse(id, CertificateStatus.GOOD)
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(fx.ocspKp.getPrivate()), null, new Date());
        byte[] ocsp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
        assertThat(ocspError(ocsp))
                .isEqualTo("OCSP verification failed: OCSP response carries no responder certificate");
    }

    @Test
    void aSignatoryCertificateWithoutAPersonalNumberIsRefused() throws Exception {
        BankIdFixture noSerial = new BankIdFixture("CN=" + BankIdFixture.TEST_NAME + ",C=SE");
        BankIdService verifier = new BankIdService(noSerial.anchors());
        String signature = noSerial.signedResponseBase64("Text");

        BankIdService.BankIdResult r = verifier.verify(signature, noSerial.ocspResponseBase64(signature));

        assertThat(r.isValid()).isFalse();
        assertThat(r.getError()).isEqualTo("No personalNumber in certificate");
    }

    // ---- XML-DSig preconditions and Id registration -----------------------------------------

    @Test
    void theSignatureElementMustBeThereAndUnique() throws Exception {
        X509Certificate cert = fx.personCert;
        assertThat(BankIdService.verifyXmlSignature(parse("<root/>"), cert))
                .isEqualTo("No XML-DSig Signature element present");
        assertThat(BankIdService.verifyXmlSignature(parse("<root xmlns:ds=\"" + DSIG + "\">"
                + "<ds:Signature/><ds:Signature/></root>"), cert))
                .isEqualTo("Multiple XML-DSig Signature elements present — ambiguous");
        assertThat(BankIdService.verifyXmlSignature(parse("<ds:Signature xmlns:ds=\"" + DSIG + "\"/>"), cert))
                .startsWith("XML-DSig verification error: ");
        assertThat(BankIdService.verifyXmlSignature(
                parseBase64(fx.signedResponseBase64("Text", false, true)), cert))
                .isEqualTo("Multiple bankIdSignedData elements present — ambiguous");
        assertThat(BankIdService.verifyXmlSignature(parseBase64(fx.signedResponseBase64("Text")), cert))
                .isNull();
    }

    @Test
    void onlyBankIdSignedDataIdsAreRegisteredAndCounted() throws Exception {
        Document one = parse("<r><bankIdSignedData ID=\"a\"/><other Id=\"b\"/><bankIdSignedData/></r>");
        assertThat(BankIdService.markBankIdSignedDataId(one)).isEqualTo(1);
        assertThat(one.getElementById("a")).isNotNull();
        assertThat(one.getElementById("b")).isNull();

        assertThat(BankIdService.markBankIdSignedDataId(parse("<r/>"))).isZero();
        assertThat(BankIdService.markBankIdSignedDataId(
                parse("<r><bankIdSignedData id=\"a\"/><bankIdSignedData Id=\"b\"/></r>"))).isEqualTo(2);
    }

    // ---- certificates ----------------------------------------------------------------------

    @Test
    void certificatesAreReadWithOrWithoutTheXmldsigNamespace() throws Exception {
        String cert = certB64(fx.personCert);
        Document prefixed = parse("<ds:Signature xmlns:ds=\"" + DSIG + "\"><ds:KeyInfo><ds:X509Data>"
                + "<ds:X509Certificate>" + cert + "</ds:X509Certificate>"
                + "<ds:X509Certificate> </ds:X509Certificate>"
                + "</ds:X509Data></ds:KeyInfo></ds:Signature>");
        Document plain = parse("<Signature><X509Certificate>\n" + cert + "\n</X509Certificate></Signature>");

        assertThat(BankIdService.extractCertificates(prefixed)).containsExactly(fx.personCert);
        assertThat(BankIdService.extractCertificates(plain)).containsExactly(fx.personCert);
    }

    @Test
    void thePinnedRootIsDroppedFromTheSubmittedPathAndAddedToTheValidatedOne() {
        List<String> errors = new ArrayList<>();
        BankIdService.ChainCheck withRoot = service.verifyCertificateChain(
                List.of(fx.personCert, fx.bankCaCert, fx.rootCert), errors);
        assertThat(withRoot.valid()).isTrue();
        assertThat(errors).isEmpty();

        BankIdService.ChainCheck caOnly = service.verifyCertificateChain(List.of(fx.bankCaCert), errors);
        assertThat(caOnly.valid()).isTrue();
        assertThat(caOnly.validatedPath()).containsExactly(fx.bankCaCert, fx.rootCert);

        BankIdService.ChainCheck rootOnly = service.verifyCertificateChain(List.of(fx.rootCert), errors);
        assertThat(rootOnly.valid()).isFalse();
        assertThat(errors).containsExactly("Certificate chain contains no certificate below a pinned BankID root");
    }

    // ---- text and DN helpers ---------------------------------------------------------------

    @Test
    void elementTextIsTrimmedAndAbsentIsNull() throws Exception {
        Element root = parse("<r><a> x </a><srvInfo/><srvInfo><name> n </name></srvInfo></r>")
                .getDocumentElement();
        assertThat(BankIdService.firstElementText(root, "a")).isEqualTo("x");
        assertThat(BankIdService.firstElementText(root, "b")).isNull();
        assertThat(BankIdService.firstElementText(root, "srvInfo", "name")).isEqualTo("n");
        assertThat(BankIdService.firstElementText(root, "srvInfo", "other")).isNull();
        assertThat(BankIdService.firstElementText(root, "none", "name")).isNull();
    }

    @Test
    void base64TextIsDecodedAndAnythingElseIsKept() {
        assertThat(BankIdService.decodeBase64Text(null)).isNull();
        assertThat(BankIdService.decodeBase64Text(b64("åäö"))).isEqualTo("åäö");
        assertThat(BankIdService.decodeBase64Text("not base64!")).isEqualTo("not base64!");
    }

    @Test
    void dnFieldsAreReadByTypeAndAMissingOrMalformedDnGivesNull() {
        assertThat(BankIdService.extractDnField("CN=Test,2.5.4.5=#130c313930303031303139393939", "cn"))
                .isEqualTo("Test");
        assertThat(BankIdService.extractDnField("CN=Test,2.5.4.5=#130c313930303031303139393939", "2.5.4.5"))
                .isEqualTo("190001019999");
        assertThat(BankIdService.extractDnField("CN=Test", "O")).isNull();
        assertThat(BankIdService.extractDnField(null, "CN")).isNull();
        assertThat(BankIdService.extractDnField("not a distinguished name", "CN")).isNull();
    }

    @Test
    void derStringBytesLoseTheirTagAndLengthOnlyWhenThereIsMoreThanThat() {
        assertThat(BankIdService.decodeAnyStringBytes(new byte[] {0x13, 0x01, 'X'})).isEqualTo("X");
        assertThat(BankIdService.decodeAnyStringBytes(new byte[] {'A', 'B'})).isEqualTo("AB");
        assertThat(BankIdService.decodeAnyStringBytes(new byte[] {'A'})).isEqualTo("A");
    }
}
