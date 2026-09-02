package eu.gillstrom.hsm.testsupport;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.cert.ocsp.jcajce.JcaRespID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Builds a complete, self-consistent BankID signature and OCSP response in
 * memory: throwaway root, bank CA, personal certificate, OCSP responder
 * certificate, an XML-DSig-signed BankID response and a signed OCSP response
 * whose nonce binds to that signature.
 *
 * <p>Nothing here comes from a real BankID transaction. A recorded production
 * signature would carry a real personal identity number and the text of a real
 * agreement, neither of which belongs in a published repository. The identity
 * number below is deliberately not a valid one.</p>
 *
 * <p>A synthetic fixture is also the stronger test. A recorded signature can
 * only show that a correct case is accepted; this fixture can produce the cases
 * that matter — a revoked certificate, a response signed by the wrong key, a
 * responder from a different CA, a nonce belonging to some other signature, and
 * payload placed outside the element the signature actually covers.</p>
 */
public final class BankIdFixture {

    /** Not a valid personal identity number. */
    public static final String TEST_PERSONAL_NUMBER = "190001019999";
    public static final String TEST_NAME = "TESTPERSON TESTSSON";
    private static final String BANKID_NS = "http://www.bankid.com/signature/v1.0.0/types";

    public final KeyPair rootKp;
    public final X509Certificate rootCert;
    public final KeyPair bankCaKp;
    public final X509Certificate bankCaCert;
    public final KeyPair personKp;
    public final X509Certificate personCert;
    public final KeyPair ocspKp;
    public final X509Certificate ocspCert;

    /** A second, unrelated CA — used to build a responder from the wrong issuer. */
    public final KeyPair foreignCaKp;
    public final X509Certificate foreignCaCert;
    public final KeyPair foreignOcspKp;
    public final X509Certificate foreignOcspCert;

    /**
     * A responder certificate that carries the bank CA's DN in its issuer field
     * but is signed by its own key. Passes an issuer-DN string comparison and
     * fails a cryptographic one.
     */
    public final KeyPair rogueOcspKp;
    public final X509Certificate rogueOcspCert;

    /** A responder issued by the right CA but without EKU id-kp-OCSPSigning. */
    public final KeyPair noEkuOcspKp;
    public final X509Certificate noEkuOcspCert;

    public BankIdFixture() throws Exception {
        rootKp = TestPki.newRsaKeyPair(2048);
        rootCert = TestPki.selfSignedCa(rootKp, "Test BankID Fixture Root");

        bankCaKp = TestPki.newRsaKeyPair(2048);
        bankCaCert = TestPki.subordinateCa(bankCaKp, "Test Bank CA v1 for BankID",
                rootCert, rootKp.getPrivate());

        personKp = TestPki.newRsaKeyPair(2048);
        personCert = person(personKp, bankCaCert, bankCaKp.getPrivate());

        ocspKp = TestPki.newRsaKeyPair(2048);
        ocspCert = TestPki.ocspResponder(ocspKp, "Test Bank CA v1 for BankID OCSP Signing",
                bankCaCert, bankCaKp.getPrivate());

        foreignCaKp = TestPki.newRsaKeyPair(2048);
        foreignCaCert = TestPki.selfSignedCa(foreignCaKp, "Unrelated CA");
        foreignOcspKp = TestPki.newRsaKeyPair(2048);
        foreignOcspCert = TestPki.ocspResponder(foreignOcspKp, "Unrelated OCSP Signing",
                foreignCaCert, foreignCaKp.getPrivate());

        // Self-issued, but wearing the bank CA's issuer DN. Everything an
        // issuer-DN string comparison looks at matches.
        rogueOcspKp = TestPki.newRsaKeyPair(2048);
        rogueOcspCert = TestPki.ocspResponder(rogueOcspKp, "Test Bank CA v1 for BankID OCSP Signing",
                new X500Name(bankCaCert.getSubjectX500Principal().getName()),
                rogueOcspKp.getPrivate());

        noEkuOcspKp = TestPki.newRsaKeyPair(2048);
        noEkuOcspCert = TestPki.endEntity(noEkuOcspKp, "Test Bank CA v1 for BankID No EKU",
                bankCaCert, bankCaKp.getPrivate());
    }

    /** The anchor set to hand to the package-private BankIdService constructor. */
    public java.util.Set<java.security.cert.TrustAnchor> anchors() {
        return Collections.singleton(new java.security.cert.TrustAnchor(rootCert, null));
    }

    private static X509Certificate person(KeyPair kp, X509Certificate issuer, PrivateKey issuerKey)
            throws Exception {
        X500Name subject = new X500Name(
                "CN=" + TEST_NAME + ",SERIALNUMBER=" + TEST_PERSONAL_NUMBER + ",C=SE");
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuer.getSubjectX500Principal().getName()),
                BigInteger.valueOf(now), new Date(now - 60_000L), new Date(now + 3600_000L),
                subject, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    // ------------------------------------------------------------------
    // Signature
    // ------------------------------------------------------------------

    /** Default usrNonVisibleData payload when a test does not bind a request. */
    public static final String DEFAULT_NON_VISIBLE = "dold nyttolast";

    /** A signed BankID response, base64-encoded exactly as the API returns it. */
    public String signedResponseBase64(String visibleText) throws Exception {
        return signedResponseBase64(visibleText, false, false);
    }

    /**
     * A signed BankID response carrying a specific {@code usrNonVisibleData}
     * payload — used to exercise the canonical request binding produced by
     * {@code BankIdService.expectedBinding(...)}.
     */
    public String signedResponseBoundTo(String visibleText, String nonVisibleData) throws Exception {
        return signedResponseBase64(visibleText, false, false, nonVisibleData);
    }

    /**
     * @param injectOutside  place a second usrVisibleData outside the signed
     *                       element and earlier in document order
     * @param duplicateData  emit two bankIdSignedData elements
     */
    public String signedResponseBase64(String visibleText,
                                       boolean injectOutside,
                                       boolean duplicateData) throws Exception {
        return signedResponseBase64(visibleText, injectOutside, duplicateData, DEFAULT_NON_VISIBLE);
    }

    public String signedResponseBase64(String visibleText,
                                       boolean injectOutside,
                                       boolean duplicateData,
                                       String nonVisibleData) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();

        Element signedData = signedDataElement(doc, visibleText, "bidSignedData", nonVisibleData);
        signedData.setIdAttribute("Id", true);

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        // BankID's profile applies inclusive c14n to the referenced element.
        // The enveloped-signature transform would be wrong here: the signature
        // envelopes the data, the data does not contain the signature.
        Reference ref = fac.newReference("#bidSignedData",
                fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(fac.newTransform(CanonicalizationMethod.INCLUSIVE,
                        (TransformParameterSpec) null)),
                null, null);
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                List.of(ref));

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509 = kif.newX509Data(List.of(personCert, bankCaCert));
        KeyInfo ki = kif.newKeyInfo(List.of(x509));

        XMLObject obj = fac.newXMLObject(List.of(new javax.xml.crypto.dom.DOMStructure(signedData)),
                null, null, null);
        XMLSignature signature = fac.newXMLSignature(si, ki, List.of(obj), null, null);

        // sign() appends the generated <Signature> to the parent node it is
        // given, so the parent is the Document itself: the signature becomes
        // the document element, which is the shape BankID returns. Signing into
        // a scratch element and moving the result afterwards does not work —
        // inclusive c14n takes the ancestor namespace context into account, so
        // relocating the subtree changes the canonical form the digest was
        // computed over.
        DOMSignContext dsc = new DOMSignContext(personKp.getPrivate(), doc);
        dsc.setIdAttributeNS(signedData, null, "Id");
        signature.sign(dsc);

        // The decoys go into an extra <Object>, which is valid XML-DSig and is
        // where an attacker could actually put them: inside the signature
        // element but outside the Reference's coverage. Appending them directly
        // to <Signature> would produce a document that will not even unmarshal.
        if (injectOutside) {
            Element decoyObject = doc.createElementNS(XMLSignature.XMLNS, "Object");
            Element decoy = doc.createElementNS(BANKID_NS, "usrVisibleData");
            decoy.setTextContent(b64("INJICERAD TEXT SOM INGEN SIGNERAT"));
            decoyObject.appendChild(decoy);
            Element root = doc.getDocumentElement();
            root.insertBefore(decoyObject, root.getFirstChild());
        }
        if (duplicateData) {
            Element decoyObject = doc.createElementNS(XMLSignature.XMLNS, "Object");
            decoyObject.appendChild(signedDataElement(doc, "ANNAN TEXT", "otherSignedData",
                    DEFAULT_NON_VISIBLE));
            doc.getDocumentElement().appendChild(decoyObject);
        }
        byte[] xml = serialise(doc);
        if (!injectOutside && !duplicateData) {
            selfCheck(xml);
        }
        return Base64.getEncoder().encodeToString(xml);
    }

    /**
     * Diagnostic: re-parse the serialised signature and validate it the same way
     * the service does. Isolates a fixture that signs incorrectly from a service
     * that verifies incorrectly, instead of leaving one opaque "did not
     * validate" for both.
     */
    private void selfCheck(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder()
                .parse(new java.io.ByteArrayInputStream(xml));

        org.w3c.dom.NodeList sigs =
                doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (sigs.getLength() != 1) {
            throw new IllegalStateException(
                    "FIXTURE: expected exactly one Signature element, found " + sigs.getLength());
        }
        org.w3c.dom.NodeList datas = doc.getElementsByTagName("bankIdSignedData");
        for (int i = 0; i < datas.getLength(); i++) {
            ((Element) datas.item(i)).setIdAttribute("Id", true);
        }

        javax.xml.crypto.dsig.dom.DOMValidateContext vc =
                new javax.xml.crypto.dsig.dom.DOMValidateContext(
                        personCert.getPublicKey(), sigs.item(0));
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        XMLSignature sig = fac.unmarshalXMLSignature(vc);

        boolean sv = sig.getSignatureValue().validate(vc);
        StringBuilder refs = new StringBuilder();
        for (Object o : sig.getSignedInfo().getReferences()) {
            Reference r = (Reference) o;
            refs.append(" uri=").append(r.getURI()).append(" ok=").append(r.validate(vc));
        }
        if (!sig.validate(vc)) {
            java.nio.file.Path dump = java.nio.file.Path.of("target", "fixture-signature.xml");
            java.nio.file.Files.createDirectories(dump.getParent());
            java.nio.file.Files.write(dump, xml);
            throw new IllegalStateException(
                    "FIXTURE self-check failed: signatureValue=" + sv + " references:" + refs
                            + " (XML dumped to " + dump.toAbsolutePath() + ")");
        }
    }

    private Element signedDataElement(Document doc, String visibleText, String id,
                                      String nonVisibleData) {
        Element sd = doc.createElementNS(BANKID_NS, "bankIdSignedData");
        // createElementNS sets the namespace URI but adds no xmlns attribute
        // node. Java's c14n builds namespace declarations from attribute nodes,
        // so without this the canonical form at signing time lacks the
        // declaration that serialisation adds and re-parsing turns into a real
        // attribute — and the reference digest fails to verify.
        sd.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", BANKID_NS);
        sd.setAttribute("Id", id);
        Element vis = doc.createElementNS(BANKID_NS, "usrVisibleData");
        vis.setAttribute("charset", "UTF-8");
        vis.setTextContent(b64(visibleText));
        sd.appendChild(vis);
        Element nonVis = doc.createElementNS(BANKID_NS, "usrNonVisibleData");
        nonVis.setTextContent(b64(nonVisibleData));
        sd.appendChild(nonVis);
        Element srv = doc.createElementNS(BANKID_NS, "srvInfo");
        Element name = doc.createElementNS(BANKID_NS, "name");
        name.setTextContent(b64("name=Testbolaget,serialNumber=5566778899,o=Testbank,c=SE"));
        srv.appendChild(name);
        sd.appendChild(srv);
        return sd;
    }

    private static String b64(String plain) {
        return Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] serialise(Document doc) throws Exception {
        Transformer t = TransformerFactory.newInstance().newTransformer();
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        t.transform(new DOMSource(doc), new StreamResult(out));
        return out.toByteArray();
    }

    // ------------------------------------------------------------------
    // OCSP
    // ------------------------------------------------------------------

    /** A well-formed, good-status OCSP response bound to the given signature. */
    public String ocspResponseBase64(String signatureBase64) throws Exception {
        return ocspResponse(signatureBase64, CertificateStatus.GOOD, ocspCert,
                ocspKp.getPrivate(), true);
    }

    public String ocspRevoked(String signatureBase64) throws Exception {
        return ocspResponse(signatureBase64, new RevokedStatus(new Date(), 0), ocspCert,
                ocspKp.getPrivate(), true);
    }

    /** Signed with a key that does not belong to the responder certificate. */
    public String ocspWrongSignature(String signatureBase64) throws Exception {
        return ocspResponse(signatureBase64, CertificateStatus.GOOD, ocspCert,
                foreignOcspKp.getPrivate(), true);
    }

    /** Responder issued by an unrelated CA. */
    public String ocspForeignIssuer(String signatureBase64) throws Exception {
        return ocspResponse(signatureBase64, CertificateStatus.GOOD, foreignOcspCert,
                foreignOcspKp.getPrivate(), true);
    }

    /**
     * Response signed by a self-issued responder certificate whose issuer DN is
     * a copy of the bank CA's. The response signature verifies under the
     * responder certificate, and the issuer DN comparison passes — only a
     * cryptographic check against the real issuing CA's public key rejects it.
     */
    public String ocspSelfIssuedResponder(String signatureBase64) throws Exception {
        return ocspResponse(signatureBase64, CertificateStatus.GOOD, rogueOcspCert,
                rogueOcspKp.getPrivate(), true);
    }

    /** Responder issued by the correct CA but lacking EKU id-kp-OCSPSigning. */
    public String ocspResponderWithoutEku(String signatureBase64) throws Exception {
        return ocspResponse(signatureBase64, CertificateStatus.GOOD, noEkuOcspCert,
                noEkuOcspKp.getPrivate(), true);
    }

    public String ocspWithoutNonce(String signatureBase64) throws Exception {
        return ocspResponse(signatureBase64, CertificateStatus.GOOD, ocspCert,
                ocspKp.getPrivate(), false);
    }

    private String ocspResponse(String signatureBase64,
                                CertificateStatus status,
                                X509Certificate responderCert,
                                PrivateKey signingKey,
                                boolean withNonce) throws Exception {
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(
                new JcaRespID(responderCert.getSubjectX500Principal()));

        CertificateID certId = new JcaCertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                bankCaCert, personCert.getSerialNumber());
        // In BouncyCastle this overload's Date argument is nextUpdate, not
        // thisUpdate — passing "now" produces a response that is already stale.
        Date nextUpdate = new Date(System.currentTimeMillis() + 3600_000L);
        builder.addResponse(certId, status, nextUpdate, (Extensions) null);

        if (withNonce) {
            byte[] head = MessageDigest.getInstance("SHA-1")
                    .digest(signatureBase64.getBytes(StandardCharsets.UTF_8));
            byte[] nonce = new byte[32];
            System.arraycopy(head, 0, nonce, 0, head.length);
            builder.setResponseExtensions(new Extensions(new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce))));
        }

        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        return Base64.getEncoder().encodeToString(new OCSPRespBuilder()
                .build(OCSPRespBuilder.SUCCESSFUL,
                        builder.build(cs, new org.bouncycastle.cert.X509CertificateHolder[] {
                                new JcaX509CertificateHolder(responderCert) }, new Date()))
                .getEncoded());
    }
}
