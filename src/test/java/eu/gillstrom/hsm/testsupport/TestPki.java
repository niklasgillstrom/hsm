package eu.gillstrom.hsm.testsupport;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Pure-BouncyCastle test PKI builder. Builds throwaway RSA key pairs and issues
 * self-signed roots and issuer-signed leaves entirely in-memory, so tests are
 * self-contained and never need external fixtures.
 */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    private TestPki() {
    }

    /** Generate an RSA key pair. 2048 is plenty for tests and keeps them fast. */
    public static KeyPair newRsaKeyPair(int bits) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(bits, new SecureRandom());
        return kpg.generateKeyPair();
    }

    /** Self-signed CA certificate (basicConstraints CA:TRUE, keyCertSign usage). */
    public static X509Certificate selfSignedCa(KeyPair kp, String cn) throws Exception {
        X500Name subject = new X500Name("CN=" + cn);
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter = new Date(now + 3600_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                subject, nextSerial(), notBefore, notAfter, subject, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    /** Issue a subordinate CA certificate under the given issuer. */
    public static X509Certificate subordinateCa(
            KeyPair subjectKp, String subjectCn,
            X509Certificate issuerCert, PrivateKey issuerKey) throws Exception {
        X500Name subject = new X500Name("CN=" + subjectCn);
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter = new Date(now + 3600_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuerCert.getSubjectX500Principal().getName()),
                nextSerial(), notBefore, notAfter, subject, subjectKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    /** Issue an end-entity signing certificate under the given issuer. */
    public static X509Certificate endEntity(
            KeyPair subjectKp, String subjectCn,
            X509Certificate issuerCert, PrivateKey issuerKey) throws Exception {
        X500Name subject = new X500Name("CN=" + subjectCn);
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter = new Date(now + 3600_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuerCert.getSubjectX500Principal().getName()),
                nextSerial(), notBefore, notAfter, subject, subjectKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    /**
     * Issue an OCSP responder certificate under the given issuer: end-entity,
     * digitalSignature, plus Extended Key Usage {@code id-kp-OCSPSigning},
     * which is what a CA uses to delegate response signing to a responder.
     */
    public static X509Certificate ocspResponder(
            KeyPair subjectKp, String subjectCn,
            X509Certificate issuerCert, PrivateKey issuerKey) throws Exception {
        return ocspResponder(subjectKp, subjectCn,
                new X500Name(issuerCert.getSubjectX500Principal().getName()), issuerKey);
    }

    /**
     * As above, but with the issuer DN and the signing key supplied separately.
     * A test can therefore build a responder certificate that <em>claims</em> to
     * come from a given CA while being signed by some other key — the shape an
     * attacker would use against an issuer-DN string comparison.
     */
    public static X509Certificate ocspResponder(
            KeyPair subjectKp, String subjectCn,
            X500Name issuerDn, PrivateKey signingKey) throws Exception {
        X500Name subject = new X500Name("CN=" + subjectCn);
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter = new Date(now + 3600_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerDn, nextSerial(), notBefore, notAfter, subject, subjectKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    /**
     * A PKCS#10 certification request whose signature is produced by
     * {@code signingKey}. Passing the private key belonging to
     * {@code subjectKp} yields a well-formed CSR; passing any other private key
     * yields a CSR that fails proof of possession while still parsing.
     */
    public static String csrPem(KeyPair subjectKp, String subjectCn, PrivateKey signingKey)
            throws Exception {
        JcaPKCS10CertificationRequestBuilder b = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=" + subjectCn), subjectKp.getPublic());
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        PKCS10CertificationRequest csr = b.build(cs);
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(csr.getEncoded());
        return "-----BEGIN CERTIFICATE REQUEST-----\n" + b64
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }

    /**
     * DER encoding of a CSR given in PEM form — the same derivation a client
     * performs before hashing the CSR into the BankID request binding.
     */
    public static byte[] csrDer(String csrPem) {
        String body = csrPem
                .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(body);
    }

    /** Serialise an X.509 certificate to a PEM string. */
    public static String toPem(X509Certificate cert) throws Exception {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    private static BigInteger nextSerial() {
        return BigInteger.valueOf(SERIAL.incrementAndGet());
    }
}
