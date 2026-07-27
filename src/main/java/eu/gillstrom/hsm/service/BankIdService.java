package eu.gillstrom.hsm.service;

import lombok.Data;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
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
import java.security.MessageDigest;
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
     * Pinned BankID root certificates for the signature chain.
     *
     * <p>The trust anchor must never be taken from the chain the caller
     * submits. Doing so lets an attacker present a self-signed root of their
     * own making, together with a user certificate carrying any personal
     * identity number they choose, and have the whole chain validate.</p>
     *
     * <p>These are the {@code OU=BankID Member Banks CA} roots, which anchor
     * end-user certificates. A BankID signature chains user certificate to
     * issuing bank CA to bank CA to root, e.g.
     * {@code NIKLAS GILLSTROM -> SEB Customer CA3 v1 for BankID -> SEB CA v1
     * for BankID -> BankID Root CA v1}. The intermediates travel inside the
     * signature, so only the root has to be pinned, and one anchor covers
     * every issuing bank.</p>
     *
     * <p>Not to be confused with {@code BankID SSL Root CA v1}
     * ({@code OU=Infrastructure CA}), which anchors the mTLS channel to the
     * BankID RP API and is a different hierarchy. Pinning that root here would
     * reject every valid signature.</p>
     *
     * <p>Production: {@code BankID Root CA v1}, SKI
     * {@code 67:8A:BA:B2:EA:48:1C:7A:F5:3B:68:37:27:72:06:EB:91:63:CB:53},
     * valid until 2034-12-31. Test: {@code Test BankID Root CA v1 Test}, SKI
     * {@code 4A:F7:A3:6A:08:DA:08:38:17:19:53:28:C8:DA:A6:D6:34:D8:5A:BA}.
     * Both are delivered by BankID on request; verify a candidate by checking
     * that its SKI equals the Authority Key Identifier of the bank CA at the
     * top of a real signature chain.</p>
     */
    private static final String BANKID_ROOT_CA_V1 = """
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            """;

    private static final String TEST_BANKID_ROOT_CA_V1_TEST = """
            -----BEGIN CERTIFICATE-----
            MIIF0jCCA7qgAwIBAgIISpGbuE9LL/0wDQYJKoZIhvcNAQENBQAwbTEkMCIGA1UE
            CgwbRmluYW5zaWVsbCBJRC1UZWtuaWsgQklEIEFCMR8wHQYDVQQLDBZCYW5rSUQg
            TWVtYmVyIEJhbmtzIENBMSQwIgYDVQQDDBtUZXN0IEJhbmtJRCBSb290IENBIHYx
            IFRlc3QwHhcNMTEwOTIyMTQwMTMzWhcNMzQxMjMxMTQwMTMzWjBtMSQwIgYDVQQK
            DBtGaW5hbnNpZWxsIElELVRla25payBCSUQgQUIxHzAdBgNVBAsMFkJhbmtJRCBN
            ZW1iZXIgQmFua3MgQ0ExJDAiBgNVBAMMG1Rlc3QgQmFua0lEIFJvb3QgQ0EgdjEg
            VGVzdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANPXoOB9BQOW8i2C
            Kk7U/d8rFNB0ktVlcgBSh8CKvnTsW3i+NrAM5LY9jgAO9vkHT3bl3nK626zePhmh
            dhVXMKAanbcF/NJ/oSF+DKCGx/VgPmCCqVyTMLjID/59diiLg3xNH3NaaBM69qnw
            5yOCYkB2wXxcATLO0eTxvL0vdKGJ2HU2AcEtaMMxrScuNCztPuwjYNP0KrYI+y/J
            Gkf2dBhomAhDLdQSSW3zXqYgbQvJ8La2ECgo3rGQQRZG9/5MZ5dOWtpAx0ybeCbh
            CPO8XIBCHrPZxv60gZK1CTwlZUoMTBSivv+vmFrH8JdmUnOP9e/wNhuM9/fQ0h5t
            4BGXoz8M5nxdH6uNJG5SpdxaXYflezBb7YdjgNiF9Yqo3DYTRrZT7dyRLYqlmKQh
            T1pqEov1tkXktQF8r1QJkTJO3x1QEzMNCnHyN8iDOqENSE4nhkzU9ESbXNOhFpnc
            XJqoFwvbeAJpV7fVwn+Jumyc/zsD9t+1Vo1lM95q1geVPfnA5z7NZ+uaayJx4DhL
            MvufDI17fqgiWHe+BMA/vGd8OjFK3JUmCV+7QeG/Z3JWbzU0GeDljqO+H4CQ0+LO
            4E4JGEZtxfUu4/XuOkCqiZ4/shoPOOxaXcZlBEMHsDzei0tNSKIxB+PoDTje/BQC
            lunVZvjcG2ehpeF540EXgzzECaNLAgMBAAGjdjB0MB0GA1UdDgQWBBRK96NqCNoI
            OBcZUyjI2qbWNNhaujAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFEr3o2oI
            2gg4FxlTKMjaptY02Fq6MBEGA1UdIAQKMAgwBgYEKgMEBTAOBgNVHQ8BAf8EBAMC
            AQYwDQYJKoZIhvcNAQENBQADggIBAJVcP9Sm2tukKW0Qx8EZG9gdXfCmNMrHXF3g
            via5zpuSMl9wdXHd1FPdGFshRZJ2sW4mb9vRI81vBIXMFVtLZFzeGHoKyz1g8hfj
            uuLKpItw0OwVNdvSRq/TKKxjVKpvt50Eydgnz4Q59YkFlGVyi7+z74mGfvN06Ssj
            2WIRtr3UD+IC6Tie6Lm/zuZs4gu0ZP/fddKh7gC3syHLNXQmN+9Y0wkdO7H98K/9
            uuIrxWtSOFVatxesw7XJRnq+uYI0IdP8xP8U4S680rTse7nsTguQxzRs2vOyoaXm
            Fdf7XQ03btd15Z4yJlEfs9/4ohgafMs49PMkACqyX45/4WBygO0QwMGVIUnKNFBt
            /I+0T2SkWFa2JdcRCSTObb7tesoeTIPgI9UcrMvNOG3gxGpB/H5/s7jTV0AOoDgM
            hOxieGgyTsZ3oP0k6bc47FJ4nE+vifAluyeXioB5JaN2kvm8eqfzC05zSF40V9GA
            zElVDbsBPR/2CE6CMyR+eqip4gDSZ6mnZYPeBecEXU4Xu+RAgqYxjKosfxOpMZsN
            +2BSm5QSRLhHacPQTnoQxujnGuUzh5TdAbWqmS0cKEZJ+CACmVLyOphdRoeEQCqQ
            8DYAyOtq2S4+hAJW+2Xq4NCdvmjm99r2RFkibSlLtqctj1JyzUC6huUiQXx9KZ8n
            FA0TsFHG
            -----END CERTIFICATE-----
            """;

    private final Set<TrustAnchor> bankIdTrustAnchors;

    public BankIdService() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            this.bankIdTrustAnchors = Set.of(
                    new TrustAnchor(loadPinnedRoot(cf, BANKID_ROOT_CA_V1), null),
                    new TrustAnchor(loadPinnedRoot(cf, TEST_BANKID_ROOT_CA_V1_TEST), null));
        } catch (Exception e) {
            // Fail-closed: without pinned roots there is nothing to anchor
            // against, so refuse to construct the bean and let startup fail.
            throw new IllegalStateException(
                    "Failed to load pinned BankID root certificates - BankIdService cannot be constructed", e);
        }
    }

    /**
     * Test seam. The pinned roots are compile-time constants, so a synthetic
     * chain built in a unit test can never validate against them. This
     * constructor lets a test supply its own anchors and exercise the real
     * validation logic; production code uses the no-arg constructor and cannot
     * reach this one.
     */
    BankIdService(Set<TrustAnchor> trustAnchors) {
        this.bankIdTrustAnchors = Set.copyOf(trustAnchors);
    }

    private static X509Certificate loadPinnedRoot(CertificateFactory cf, String pem) throws Exception {
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.trim().getBytes(StandardCharsets.UTF_8)));
    }

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
                OcspCheck ocsp = checkOcsp(ocspBase64, userCert, signatureBase64);
                if (!ocsp.ok()) {
                    return BankIdResult.invalid("OCSP verification failed: "
                            + String.join("; ", ocsp.errors));
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

            // Read the payload only from inside the element the signature's
            // Reference actually covers. Reading with getElementsByTagName over
            // the whole document meant an attacker could place a
            // usrVisibleData element outside the signed data, earlier in
            // document order, and have it returned instead of the signed one —
            // the signature would still validate, because the injected element
            // is not part of what was signed.
            Element signedData = uniqueSignedData(doc);
            if (signedData == null) {
                return BankIdResult.invalid("Missing or ambiguous bankIdSignedData element");
            }

            String usrVisibleData = decodeBase64Text(firstElementText(signedData, "usrVisibleData"));
            String usrNonVisibleData = decodeBase64Text(firstElementText(signedData, "usrNonVisibleData"));

            String relyingPartyName = null;
            String relyingPartyOrgNumber = null;
            String srvInfoName = firstElementText(signedData, "srvInfo", "name");
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

            String signatureTimeRaw = firstElementText(signedData, "signingTime");

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
            // Anchor against the pinned roots, never against a certificate the
            // caller supplied. Any cert in the submitted chain that is already
            // one of our anchors is dropped: PKIX rejects a path containing the
            // anchor itself.
            List<X509Certificate> path = new ArrayList<>();
            for (X509Certificate c : certs) {
                boolean pinnedAnchor = bankIdTrustAnchors.stream().anyMatch(a ->
                        a.getTrustedCert().getSubjectX500Principal().equals(c.getSubjectX500Principal()));
                if (!pinnedAnchor) {
                    path.add(c);
                }
            }
            if (path.isEmpty()) {
                errors.add("Certificate chain contains no certificate below a pinned BankID root");
                return false;
            }
            PKIXParameters params = new PKIXParameters(bankIdTrustAnchors);
            params.setRevocationEnabled(false);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(cf.generateCertPath(path), params);
            return true;
        } catch (Exception e) {
            errors.add("Chain validation error: " + e.getMessage());
            return false;
        }
    }


    /**
     * OCSP verification using BouncyCastle. Confirms that the OCSP response
     * refers to the same certificate serial as the user certificate, and
     * returns the OCSP {@code producedAt} timestamp as the authoritative
     * signing time.
     */
    /**
     * OCSP verification following BankID's published procedure for verifying
     * signatures, which prescribes seven steps. This method covers steps 1, 2,
     * 3, 5 and 6; steps 4 and 7 (certificate chain and XML-DSig signature) are
     * handled by {@link #verifyCertificateChain} and {@link #verifyXmlSignature}.
     *
     * <p>The previous implementation matched only the certificate serial number
     * and read {@code producedAt}. It never looked at {@code CertStatus}, so a
     * revoked certificate passed; it never verified the signature on the
     * response, so the response could be fabricated; and it never checked the
     * nonce, so a response issued for one signature could be replayed against
     * another.</p>
     *
     * <p><b>Nonce binding.</b> BankID's procedure says the OCSP nonce must
     * match "digest of signature" without specifying the construction. Measured
     * against production responses, the first 20 bytes of the 32-byte nonce are
     * SHA-1 over the base64 string of the signature — the string as transmitted
     * and stored, not the decoded XML bytes. The remaining 12 bytes differ
     * between responses and are not derivable from the signature, so only the
     * first 20 are compared. That is sufficient for the property the step
     * exists to establish: a response issued for a different signature is
     * rejected.</p>
     */
    private OcspCheck checkOcsp(String ocspBase64, X509Certificate userCert, String signatureBase64) {
        OcspCheck out = new OcspCheck();
        try {
            OCSPResp resp = new OCSPResp(Base64.getDecoder().decode(ocspBase64));
            if (resp.getStatus() != OCSPResp.SUCCESSFUL) {
                out.errors.add("OCSP responder returned status " + resp.getStatus());
                return out;
            }
            if (!(resp.getResponseObject() instanceof BasicOCSPResp basic)) {
                out.errors.add("OCSP response is not a BasicOCSPResp");
                return out;
            }

            // Step 1-2: the responder certificate, and the signature over the
            // response. Without these the whole response is attacker-supplied.
            X509CertificateHolder[] holders = basic.getCerts();
            if (holders == null || holders.length == 0) {
                out.errors.add("OCSP response carries no responder certificate");
                return out;
            }
            X509Certificate signerCert =
                    new JcaX509CertificateConverter().getCertificate(holders[0]);
            if (!basic.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .build(signerCert.getPublicKey()))) {
                out.errors.add("OCSP response signature is not valid");
                return out;
            }
            signerCert.checkValidity();

            // Step 5: the responder must be issued by the same CA as the user
            // certificate. A valid response from some other CA's responder says
            // nothing about this certificate.
            if (!signerCert.getIssuerX500Principal().equals(userCert.getIssuerX500Principal())) {
                out.errors.add("OCSP signer is not issued by the same CA as the BankID certificate");
            }

            // Step 3: the actual revocation status.
            SingleResp match = null;
            for (SingleResp single : basic.getResponses()) {
                if (single.getCertID() != null
                        && single.getCertID().getSerialNumber().equals(userCert.getSerialNumber())) {
                    match = single;
                    break;
                }
            }
            if (match == null) {
                out.errors.add("OCSP response contains no entry for certificate serial "
                        + userCert.getSerialNumber());
                return out;
            }
            out.matchesCertificate = true;
            if (match.getCertStatus() != null) {
                // BouncyCastle represents GOOD as null; anything else is revoked
                // or unknown.
                out.errors.add("Certificate status is not good: " + match.getCertStatus());
            }
            if (match.getNextUpdate() != null && match.getNextUpdate().toInstant().isBefore(Instant.now())) {
                out.errors.add("OCSP response is stale (nextUpdate in the past)");
            }
            if (basic.getProducedAt() != null) {
                out.producedAt = basic.getProducedAt().toInstant();
            }

            // Step 6: nonce binds this response to this signature.
            Extension nonceExt = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (nonceExt == null) {
                out.errors.add("OCSP response carries no nonce");
            } else if (signatureBase64 != null) {
                byte[] nonce = nonceExt.getExtnValue().getOctets();
                byte[] expected = MessageDigest.getInstance("SHA-1")
                        .digest(signatureBase64.getBytes(StandardCharsets.UTF_8));
                if (nonce.length < expected.length
                        || !MessageDigest.isEqual(
                                java.util.Arrays.copyOf(nonce, expected.length), expected)) {
                    out.errors.add("OCSP nonce does not bind to this signature");
                }
            }
        } catch (Exception e) {
            log.warn("OCSP verification failure: {}", e.getMessage());
            out.errors.add("OCSP verification error: " + e.getMessage());
        }
        return out;
    }

    /**
     * Return the text content of the first element matching {@code tagName},
     * trimmed. Returns {@code null} if no such element exists.
     */
    /**
     * The single {@code bankIdSignedData} element, or {@code null} if it is
     * missing or duplicated. Everything the caller is told about the signature
     * must be read from inside this element — it is the only part the
     * signature's Reference covers.
     */
    private Element uniqueSignedData(Document doc) {
        NodeList nodes = doc.getElementsByTagName("bankIdSignedData");
        if (nodes.getLength() != 1 || !(nodes.item(0) instanceof Element el)) {
            return null;
        }
        return el;
    }

    private String firstElementText(Element scope, String tagName) {
        NodeList nl = scope.getElementsByTagName(tagName);
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
    private String firstElementText(Element scope, String parentTag, String childTag) {
        NodeList parents = scope.getElementsByTagName(parentTag);
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
        final List<String> errors = new ArrayList<>();

        boolean ok() {
            return matchesCertificate && errors.isEmpty();
        }
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
