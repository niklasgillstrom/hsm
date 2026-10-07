package eu.gillstrom.hsm.service;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Which keys and CSR signature algorithms a certificate request may use.
 *
 * <p>Keys are named {@code RSA-<modulus bits>} or {@code EC-<curve name>}
 * (e.g. {@code RSA-4096}, {@code EC-secp384r1}). CSR signature algorithms use
 * the JCA names (e.g. {@code SHA256withRSA}); comparison ignores case. Both
 * lists are exact allow-lists: anything not named is refused.</p>
 *
 * <p>The defaults admit RSA-4096 keys only, and CSR signatures with SHA-256 or
 * stronger. A deployment that needs another key type, for example an EC key
 * from an HSM that produces one, has to name it explicitly in
 * {@code swish.key-policy.allowed-keys}.</p>
 */
@Component
public class KeyPolicy {

    public static final String DEFAULT_ALLOWED_KEYS = "RSA-4096";
    public static final String DEFAULT_ALLOWED_CSR_SIGNATURE_ALGORITHMS =
            "SHA256withRSA,SHA384withRSA,SHA512withRSA";

    private final Set<String> allowedKeys;
    private final Set<String> allowedCsrSignatureAlgorithms;

    public KeyPolicy(
            @Value("${swish.key-policy.allowed-keys:" + DEFAULT_ALLOWED_KEYS + "}") String allowedKeys,
            @Value("${swish.key-policy.allowed-csr-signature-algorithms:"
                    + DEFAULT_ALLOWED_CSR_SIGNATURE_ALGORITHMS + "}") String allowedCsrSignatureAlgorithms) {
        this.allowedKeys = parse(allowedKeys);
        this.allowedCsrSignatureAlgorithms = parse(allowedCsrSignatureAlgorithms);
        if (this.allowedKeys.isEmpty() || this.allowedCsrSignatureAlgorithms.isEmpty()) {
            throw new IllegalStateException("swish.key-policy: both allow-lists must name at least one entry");
        }
        for (String alg : this.allowedCsrSignatureAlgorithms) {
            if (alg.startsWith("sha1") || alg.startsWith("md")) {
                throw new IllegalStateException("swish.key-policy.allowed-csr-signature-algorithms: " + alg
                        + " is too weak (SHA-1 and MD2/MD5 are refused)");
            }
        }
    }

    /** The default policy: RSA-4096, CSR signed with SHA-256 or stronger. */
    public static KeyPolicy defaults() {
        return new KeyPolicy(DEFAULT_ALLOWED_KEYS, DEFAULT_ALLOWED_CSR_SIGNATURE_ALGORITHMS);
    }

    /**
     * @return a description of the violation, or empty if the CSR's key and
     *         signature algorithm are both allowed
     */
    public Optional<String> violation(PKCS10CertificationRequest csr, PublicKey publicKey) {
        String key = describeKey(csr.getSubjectPublicKeyInfo(), publicKey);
        if (!allowedKeys.contains(key.toLowerCase(Locale.ROOT))) {
            return Optional.of("key " + key + " is not in the allowed keys " + allowedKeys);
        }
        String sigAlg = describeSignatureAlgorithm(csr.getSignatureAlgorithm());
        if (!allowedCsrSignatureAlgorithms.contains(sigAlg.toLowerCase(Locale.ROOT))) {
            return Optional.of("CSR signature algorithm " + sigAlg
                    + " is not in the allowed algorithms " + allowedCsrSignatureAlgorithms);
        }
        return Optional.empty();
    }

    static String describeKey(SubjectPublicKeyInfo spki, PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey rsa) {
            return "RSA-" + rsa.getModulus().bitLength();
        }
        AlgorithmIdentifier alg = spki.getAlgorithm();
        if (X9ObjectIdentifiers.id_ecPublicKey.equals(alg.getAlgorithm())
                && alg.getParameters() instanceof ASN1ObjectIdentifier curve) {
            // Prefer the SEC name (secp256r1) over the X9.62 one (prime256v1),
            // so a curve is named the same way however its OID is registered.
            String name = SECNamedCurves.getName(curve);
            if (name == null) {
                name = ECNamedCurveTable.getName(curve);
            }
            return "EC-" + (name != null ? name : curve.getId());
        }
        return alg.getAlgorithm().getId();
    }

    static String describeSignatureAlgorithm(AlgorithmIdentifier alg) {
        String name = new DefaultAlgorithmNameFinder().getAlgorithmName(alg);
        // DefaultAlgorithmNameFinder answers "SHA256WITHRSA"; normalise to the JCA spelling.
        return name.replace("WITH", "with");
    }

    private static Set<String> parse(String list) {
        return Arrays.stream(list == null ? new String[0] : list.split(","))
                .map(s -> s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}
