package eu.gillstrom.hsm.util;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The one reading of a submitted CSR: the request whose signature is
 * checked and the key that is attested and certified come from the same DER.
 *
 * <p>Accepted input is exactly one PEM block, with either the
 * {@code CERTIFICATE REQUEST} or the {@code NEW CERTIFICATE REQUEST} label
 * (the same label at both ends), or bare base64 of the DER. Until 1.6.0
 * hsm read CSRs in four places: the binding hash stripped every header and
 * decoded everything that was left, the signature check read the first PEM
 * block, and mock issuance knew only the {@code CERTIFICATE REQUEST} label,
 * so two blocks in one field were hashed together but only the first was
 * verified, and a {@code NEW CERTIFICATE REQUEST} passed verification and
 * failed at issuance.</p>
 */
public final class Csrs {

    private static final Pattern PEM = Pattern.compile(
            "-----BEGIN (NEW )?CERTIFICATE REQUEST-----([A-Za-z0-9+/=\\s]*)-----END (NEW )?CERTIFICATE REQUEST-----");

    private Csrs() {
    }

    /** The DER bytes of the submitted CSR. */
    public static byte[] der(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("CSR is empty");
        }
        String text = input.trim();
        String body;
        if (text.contains("-----")) {
            Matcher m = PEM.matcher(text);
            if (!m.matches()) {
                throw new IllegalArgumentException("CSR must be exactly one PEM CERTIFICATE REQUEST block");
            }
            if ((m.group(1) == null) != (m.group(3) == null)) {
                throw new IllegalArgumentException("CSR PEM labels at BEGIN and END differ");
            }
            body = m.group(2);
        } else {
            body = text;
        }
        try {
            return Base64.getDecoder().decode(body.replaceAll("\\s+", ""));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("CSR is not base64: " + e.getMessage(), e);
        }
    }

    /** The submitted CSR, parsed from {@link #der}. */
    public static PKCS10CertificationRequest parse(String input) {
        try {
            return new PKCS10CertificationRequest(der(input));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("CSR does not parse: " + e.getMessage(), e);
        }
    }

    /** The CSR's public key, as an RSA or EC JCA key. */
    public static PublicKey publicKey(PKCS10CertificationRequest csr) throws Exception {
        var info = csr.getSubjectPublicKeyInfo();
        String algorithm = info.getAlgorithm().getAlgorithm().getId();
        String keyAlgorithm = algorithm.startsWith("1.2.840.10045") ? "EC" : "RSA";
        return KeyFactory.getInstance(keyAlgorithm).generatePublic(new X509EncodedKeySpec(info.getEncoded()));
    }

    /** The submitted CSR's public key. */
    public static PublicKey publicKey(String input) throws Exception {
        return publicKey(parse(input));
    }
}
