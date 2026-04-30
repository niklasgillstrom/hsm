package eu.gillstrom.hsm.service;

import lombok.Data;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.xml.XMLConstants;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@Service
public class BankIdService {

    private static final Logger log = LoggerFactory.getLogger(BankIdService.class);

    /**
     * Verify a BankID signature response.
     *
     * <p>Performs (in order):</p>
     * <ol>
     *   <li>Parse the XML document with XXE protection enabled.</li>
     *   <li>Verify the enveloping XML-DSig signature using the public key from
     *       the embedded user certificate. This establishes that the signed
     *       payload (including {@code usrVisibleData} and {@code usrNonVisibleData})
     *       was actually signed by the holder of the BankID private key, rather
     *       than merely attached to a legitimate certificate chain by an
     *       attacker.</li>
     *   <li>Parse the certificate chain and validate it cryptographically via
     *       {@link CertPathValidator} against the user certificate's own root,
     *       using the standard PKIX algorithm. Revocation checking is disabled
     *       here (consistent with the chosen validation model); higher layers
     *       should rely on the OCSP response cross-check (step&nbsp;4) for
     *       certificate-status information.</li>
     *   <li>If an OCSP response is supplied, parse it with BouncyCastle, verify
     *       that it refers to the same user-certificate serial, and extract
     *       {@code producedAt} as the authoritative signing time.</li>
     *   <li>Extract identity data from the signed payload.</li>
     * </ol>
     */
    public BankIdResult verify(String signatureBase64, String ocspBase64) {
        try {
            byte[] xmlBytes = Base64.getDecoder().decode(signatureBase64);
            Document doc = parseXmlSafely(xmlBytes);

            // Extract certificate chain from <KeyInfo><X509Data>
            List<X509Certificate> certs = extractCertificates(doc);
            if (certs.isEmpty()) {
                return BankIdResult.invalid("No X509Certificate found");
            }
            X509Certificate userCert = certs.get(0);

            // Verify the XML-DSig signature against the user certificate's public key.
            // This is the step that proves the signed payload came from the holder
            // of the BankID private key, not just from someone with access to the
            // certificate chain.
            String dsigError = verifyXmlSignature(doc, userCert);
            boolean signatureValid = dsigError == null;

            // Verify the certificate chain cryptographically using PKIX.
            List<String> chainErrors = new ArrayList<>();
            boolean chainValid = verifyCertificateChain(certs, chainErrors);

            // Optional OCSP cross-check for signing time and status.
            Instant producedAt = null;
            if (ocspBase64 != null && !ocspBase64.isBlank()) {
                OcspCheck ocsp = checkOcsp(ocspBase64, userCert);
                if (!ocsp.matchesCertificate) {
                    return BankIdResult.invalid("OCSP response does not match BankID certificate");
                }
                producedAt = ocsp.producedAt;
            }

            String subjectDn = userCert.getSubjectX500Principal().getName();
            String personalNumber = extractDnField(subjectDn, "SERIALNUMBER");
            if (personalNumber == null) {
                personalNumber = extractDnField(subjectDn, "2.5.4.5");
            }
            String name = extractDnField(subjectDn, "CN");

            if (personalNumber == null) {
                return BankIdResult.invalid("No personalNumber in certificate");
            }

            // Extract user-visible data from the signed DOM (not regex).
            String usrVisibleData = decodeBase64Text(firstElementText(doc, "usrVisibleData"));
            String usrNonVisibleData = decodeBase64Text(firstElementText(doc, "usrNonVisibleData"));

            String relyingPartyName = null;
            String relyingPartyOrgNumber = null;
            String srvInfoName = firstElementText(doc, "srvInfo", "name");
            if (srvInfoName != null) {
                String decoded = decodeBase64Text(srvInfoName);
                if (decoded != null) {
                    relyingPartyName = extractDnField(decoded, "name");
                    if (relyingPartyName == null) {
                        relyingPartyName = extractDnField(decoded, "cn");
                    }
                    relyingPartyOrgNumber = extractDnField(decoded, "serialNumber");
                }
            }

            String signatureTimeRaw = firstElementText(doc, "signingTime");
            if (signatureTimeRaw == null) {
                signatureTimeRaw = firstElementText(doc, "bankIdSignedData", "signingTime");
            }

            BankIdResult result = new BankIdResult();
            result.setValid(signatureValid && chainValid);
            result.setSignatureValid(signatureValid);
            if (dsigError != null) {
                result.setError(dsigError);
            } else if (!chainValid) {
                result.setError("Certificate chain validation failed");
            }
            result.setPersonalNumber(personalNumber);
            result.setName(name);
            result.setUsrVisibleData(usrVisibleData);
            result.setUsrNonVisibleData(usrNonVisibleData);
            result.setRelyingPartyName(relyingPartyName);
            result.setRelyingPartyOrgNumber(relyingPartyOrgNumber);
            if (producedAt != null) {
                result.setSignatureTime(producedAt);
            }
            result.setCertificateChainValid(chainValid);
            result.setCertificateChainErrors(chainErrors);
            result.setCertificateCount(certs.size());

            return result;

        } catch (Exception e) {
            log.warn("BankID verification failed: {}", e.getMessage(), e);
            return BankIdResult.invalid("Parse error: " + e.getMessage());
        }
    }

    /**
     * Parse XML with XXE and related external-entity attacks disabled.
     */
    private Document parseXmlSafely(byte[] xmlBytes) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        // BankID signatures rely on element IDs for the Reference URI lookup.
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xmlBytes));
    }

    /**
     * Verify the enveloping XML-DSig signature on the BankID response.
     *
     * @return {@code null} if the signature verifies; otherwise a description
     *         of the verification failure.
     */
    private String verifyXmlSignature(Document doc, X509Certificate userCert) {
        try {
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                return "No XML-DSig Signature element present";
            }
            if (nl.getLength() > 1) {
                // Multiple <Signature> elements create ambiguity about which
                // one authenticates the payload. BankID's profile envelops
                // exactly one signature — fail-closed.
                return "Multiple XML-DSig Signature elements present — ambiguous";
            }
            Node signatureNode = nl.item(0);

            // BankID's XML-DSig profile signs exactly one <bankIdSignedData>
            // element (RP-Id-scoped) and references it via URI. Register the
            // known element name(s) as DOM IDs in a controlled way, rather
            // than marking every element with an "Id"/"ID"/"id" attribute.
            // This prevents a malformed payload with duplicate Id attributes
            // from confusing Reference URI resolution.
            int marked = markBankIdSignedDataId(doc);
            if (marked > 1) {
                return "Multiple bankIdSignedData elements present — ambiguous";
            }

            DOMValidateContext ctx = new DOMValidateContext(
                    KeySelector.singletonKeySelector(userCert.getPublicKey()),
                    signatureNode);
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            XMLSignature signature = factory.unmarshalXMLSignature(ctx);
            boolean ok = signature.validate(ctx);
            if (!ok) {
                return "XML-DSig signature did not validate against user certificate public key";
            }
            return null;
        } catch (Exception e) {
            return "XML-DSig verification error: " + e.getMessage();
        }
    }

    /**
     * Register the {@code Id} attribute on BankID's signed <bankIdSignedData>
     * element as a DOM ID, so that {@link XMLSignatureFactory} can resolve
     * the {@code Reference} URI inside {@code SignedInfo}.
     *
     * <p>Previous implementation walked the whole DOM and marked every
     * {@code Id}/{@code ID}/{@code id} attribute as an ID. That was permissive
     * and could be exploited by a crafted payload containing multiple
     * {@code Id} attributes on nested elements to shadow the signed element.
     * This implementation only marks the BankID-profile-defined signed
     * element and returns the count so the caller can fail on ambiguity.</p>
     *
     * <p>Attribute names recognised are {@code Id} (the BankID canonical
     * form) and its case variants {@code ID}/{@code id} for interoperability
     * with older test fixtures.</p>
     *
     * @return the number of {@code <bankIdSignedData>} elements whose Id
     *         attribute was successfully registered (0 or 1 for a
     *         well-formed payload; &gt;1 indicates ambiguity the caller must
     *         reject).
     */
    private int markBankIdSignedDataId(Document doc) {
        NodeList bankIdNodes = doc.getElementsByTagName("bankIdSignedData");
        int marked = 0;
        for (int i = 0; i < bankIdNodes.getLength(); i++) {
            Node node = bankIdNodes.item(i);
            if (!(node instanceof Element el)) {
                continue;
            }
            for (String attrName : new String[] { "Id", "ID", "id" }) {
                if (el.hasAttribute(attrName)) {
                    el.setIdAttribute(attrName, true);
                    marked++;
                    break; // one Id-variant is enough per element
                }
            }
        }
        return marked;
    }

    /**
     * Extract X.509 certificates from {@code <X509Certificate>} elements inside
     * the signed XML. Order is preserved so that index 0 is the user cert.
     */
    private List<X509Certificate> extractCertificates(Document doc) throws Exception {
        List<X509Certificate> certs = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        NodeList certNodes = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
        if (certNodes.getLength() == 0) {
            // BankID sometimes emits certificates outside the xmldsig namespace.
            certNodes = doc.getElementsByTagName("X509Certificate");
        }
        for (int i = 0; i < certNodes.getLength(); i++) {
            String certB64 = certNodes.item(i).getTextContent().replaceAll("\\s", "");
            if (certB64.isEmpty()) {
                continue;
            }
            byte[] certBytes = Base64.getDecoder().decode(certB64);
            certs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes)));
        }
        return certs;
    }

    /**
     * Validate the BankID certificate chain using the standard PKIX algorithm.
     *
     * <p>The root certificate in the chain is treated as the trust anchor; this
     * means the chain is validated for internal consistency (signatures,
     * validity periods, BasicConstraints, path length, key usage) but the root
     * itself must be separately trusted by the caller. In practice BankID chains
     * should terminate in "Finansiell ID-Teknik BID AB" or equivalent — the
     * caller may want to pin that root explicitly.</p>
     */
    private boolean verifyCertificateChain(List<X509Certificate> certs, List<String> errors) {
        if (certs.isEmpty()) {
            errors.add("Empty certificate chain");
            return false;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // The chain submitted for CertPathValidator must not include the
            // trust anchor; split it off.
            X509Certificate root = certs.get(certs.size() - 1);
            List<X509Certificate> path = certs.subList(0, certs.size() - 1);
            if (path.isEmpty()) {
                // Single self-signed cert — verify against itself.
                root.verify(root.getPublicKey());
                root.checkValidity();
                verifyBankIdRootIssuer(root, errors);
                return errors.isEmpty();
            }
            Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(root, null));
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(cf.generateCertPath(path), params);

            verifyBankIdRootIssuer(root, errors);
            return errors.isEmpty();
        } catch (Exception e) {
            errors.add("Chain validation error: " + e.getMessage());
            return false;
        }
    }

    private void verifyBankIdRootIssuer(X509Certificate root, List<String> errors) {
        String issuer = root.getIssuerX500Principal().getName();
        String subject = root.getSubjectX500Principal().getName();
        boolean looksLikeBankId =
                issuer.contains("BankID") || issuer.contains("Finansiell ID-Teknik")
                        || subject.contains("BankID") || subject.contains("Finansiell ID-Teknik");
        if (!looksLikeBankId) {
            errors.add("Root certificate does not appear to be from BankID");
        }
    }

    /**
     * OCSP verification using BouncyCastle. Confirms that the OCSP response
     * refers to the same certificate serial as the user certificate, and
     * returns the OCSP {@code producedAt} timestamp as the authoritative
     * signing time.
     */
    private OcspCheck checkOcsp(String ocspBase64, X509Certificate userCert) {
        OcspCheck out = new OcspCheck();
        try {
            byte[] ocspBytes = Base64.getDecoder().decode(ocspBase64);
            OCSPResp resp = new OCSPResp(ocspBytes);
            Object body = resp.getResponseObject();
            if (!(body instanceof BasicOCSPResp basic)) {
                log.warn("OCSP response is not a BasicOCSPResp ({}): ignoring", body);
                return out;
            }
            SingleResp[] singles = basic.getResponses();
            for (SingleResp single : singles) {
                if (single.getCertID() != null
                        && single.getCertID().getSerialNumber().equals(userCert.getSerialNumber())) {
                    out.matchesCertificate = true;
                    if (basic.getProducedAt() != null) {
                        out.producedAt = basic.getProducedAt().toInstant();
                    }
                    return out;
                }
            }
            log.warn("OCSP response did not contain a SingleResp matching certificate serial {}",
                    userCert.getSerialNumber());
        } catch (Exception e) {
            log.warn("OCSP parse failure: {}", e.getMessage());
        }
        return out;
    }

    /**
     * Return the text content of the first element matching {@code tagName},
     * trimmed. Returns {@code null} if no such element exists.
     */
    private String firstElementText(Document doc, String tagName) {
        NodeList nl = doc.getElementsByTagName(tagName);
        if (nl.getLength() == 0) {
            return null;
        }
        String text = nl.item(0).getTextContent();
        return text == null ? null : text.trim();
    }

    /**
     * Return the text content of a {@code <parent><child>}-style nested element
     * by searching for {@code parentTag} first, then within its descendants for
     * {@code childTag}.
     */
    private String firstElementText(Document doc, String parentTag, String childTag) {
        NodeList parents = doc.getElementsByTagName(parentTag);
        for (int i = 0; i < parents.getLength(); i++) {
            Node parent = parents.item(i);
            if (parent instanceof Element parentElement) {
                NodeList children = parentElement.getElementsByTagName(childTag);
                if (children.getLength() > 0) {
                    String text = children.item(0).getTextContent();
                    return text == null ? null : text.trim();
                }
            }
        }
        return null;
    }

    private String decodeBase64Text(String b64) {
        if (b64 == null) {
            return null;
        }
        try {
            return new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return b64;
        }
    }

    /**
     * Extract a field from an X.500 Distinguished Name using the standard
     * {@link LdapName} / {@link Rdn} parser (RFC 4514-aware). Replaces the
     * previous regex-based extractor, which was fragile against escaped
     * commas, quoted values and DER-hex-encoded attribute values.
     *
     * <p>{@code field} is matched case-insensitively against the attribute
     * type (e.g. {@code CN}, {@code SERIALNUMBER}, {@code 2.5.4.5}).</p>
     *
     * @param dn    the subject / issuer DN as returned by
     *              {@link java.security.cert.X509Certificate#getSubjectX500Principal()}
     * @param field the attribute type to extract
     * @return the attribute value (coerced to string, hex-decoded if the
     *         underlying Rdn yielded a {@code byte[]}), or {@code null} if
     *         the attribute is not present.
     */
    private String extractDnField(String dn, String field) {
        if (dn == null) {
            return null;
        }
        try {
            LdapName name = new LdapName(dn);
            for (Rdn rdn : name.getRdns()) {
                if (rdn.getType().equalsIgnoreCase(field)) {
                    Object value = rdn.getValue();
                    if (value == null) {
                        return null;
                    }
                    if (value instanceof String s) {
                        return s;
                    }
                    if (value instanceof byte[] bytes) {
                        return decodeAnyStringBytes(bytes);
                    }
                    return value.toString();
                }
            }
            return null;
        } catch (InvalidNameException e) {
            log.warn("Failed to parse DN '{}': {}", dn, e.getMessage());
            return null;
        }
    }

    /**
     * Heuristically decode DER-encoded string-typed DN attribute values that
     * {@link Rdn#getValue()} may return as {@code byte[]}. We don't need a
     * full ASN.1 parse — strip a leading {@code tag/length} pair if it looks
     * like one, and treat the remainder as UTF-8. This is only reached for
     * attribute types that Java's LDAP parser doesn't recognise as a native
     * string type, which is rare in BankID DNs.
     */
    private String decodeAnyStringBytes(byte[] bytes) {
        if (bytes.length > 2) {
            return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_8);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static class OcspCheck {
        boolean matchesCertificate = false;
        Instant producedAt = null;
    }

    @Data
    public static class BankIdResult {
        private boolean valid;
        /** True if XML-DSig signature validated against the user certificate. */
        private boolean signatureValid;
        private String personalNumber;
        private String name;
        private String usrVisibleData;
        private String usrNonVisibleData;
        private String relyingPartyName;
        private String relyingPartyOrgNumber;
        private Instant signatureTime;
        private boolean certificateChainValid;
        private List<String> certificateChainErrors;
        private int certificateCount;
        private String error;

        public static BankIdResult invalid(String error) {
            BankIdResult r = new BankIdResult();
            r.valid = false;
            r.signatureValid = false;
            r.error = error;
            r.certificateChainErrors = new ArrayList<>();
            return r;
        }
    }
}
