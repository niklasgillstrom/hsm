package eu.gillstrom.hsm.verification;

/*
 * The blob layout, attribute numbers and signature schemes below are a Java
 * port of the Marvell LiquidSecurity key-attestation parser and validator in
 * Microsoft's https://github.com/Azure/azure-managed-hsm-key-attestation
 * (src/vendor/marvell/marvell_parse_key_attestation.py and
 * marvell_validate_key_attestation.py, commit 02f14d1c), used under this
 * licence:
 *
 * MIT License
 *
 * Copyright (c) Microsoft Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * Parser and verifier for Marvell LiquidSecurity key attestations, the HSM
 * behind both Azure Managed HSM and Google Cloud HSM.
 *
 * <p><strong>Provenance.</strong> Marvell's format specification is not
 * public. Everything here follows the two vendor tools that are: Microsoft's
 * MIT-licensed parser and validator (blob layout, attribute numbers, firmware
 * 2.x and 3.x signature schemes, Marvell roots) and Google's Apache-licensed
 * {@code verify_attestation_chains.py} in
 * {@code GoogleCloudPlatform/python-docs-samples} (gzip container, SHA-256
 * PKCS#1 v1.5 signature over all but the last 256 bytes, owner chain under
 * "Hawksbill Root v1 prod"). No real attestation has been run through this
 * class; see {@link #FORMAT_CONFIRMED_BY_REAL_SAMPLE}.</p>
 *
 * <p><strong>Layouts.</strong> The last 256 bytes are the signature and the
 * rest is the signed data. The attribute list starts with a header
 * {@code >III} whose second word is the attribute count, followed by that many
 * {@code >II} (type, length) records and their values. Firmware 2.x puts the
 * list at byte 20. Firmware 3.x starts with a response header {@code >IIII}
 * whose third and fourth words are the total size and buffer size; the info
 * header {@code >HHHH} sits at {@code total - (buffer + 256)} and its third
 * word is the offset of the attribute list from there. Microsoft's parser
 * picks the layout by whether a 2.x walk from byte 0 runs out of bytes. Here
 * both layouts are parsed strictly inside the signed data, and a blob that
 * parses as both, or as neither, is rejected.</p>
 *
 * <p><strong>Signature.</strong> Firmware 3.x: PKCS#1 v1.5 with the hash of
 * the partition certificate's own signature algorithm (Microsoft), which is
 * SHA-256 in Google's tool. Firmware 2.x: Microsoft's validator raises the
 * signature to the public exponent and compares only the trailing 32 bytes
 * with SHA-256 of the data, with no padding check. That check is accepted
 * here only for an exponent of at least 65537. With e = 3 and no padding, a
 * cube root modulo 2^256 forges any trailing 32 bytes without the private
 * key.</p>
 *
 * <p><strong>Key binding.</strong> Microsoft's validator binds the
 * attestation to no public key at all: it reads the key's attributes and its
 * name and version from {@code OBJ_ATTR_ID}. The Azure JSON's {@code key}
 * JWK and the cloud APIs' get-public-key calls are outside the signed blob,
 * so taking the key from them means trusting the cloud provider. The only
 * offline binding is the RSA modulus inside the signed blob. Microsoft's
 * attribute table lists the public exponent ({@code 0x0122}) but not the
 * modulus; {@link #ATTR_MODULUS} = {@code 0x0120} is PKCS#11's
 * {@code CKA_MODULUS} and is an unverified assumption until a real
 * attestation shows it.</p>
 */
public final class MarvellAttestation {

    /**
     * False until a real Azure Managed HSM or Google Cloud HSM attestation has
     * been checked against this class and committed as a test fixture. While
     * false, the Azure and Google verifiers never report a valid attestation.
     */
    public static final boolean FORMAT_CONFIRMED_BY_REAL_SAMPLE = false;

    public static final String FORMAT_UNCONFIRMED_ERROR = "MARVELL_FORMAT_UNCONFIRMED: the Marvell "
            + "attestation layout and the modulus attribute (0x0120) follow the vendors' published "
            + "tools but have not been confirmed against a real attestation; no Azure Managed HSM "
            + "or Google Cloud HSM attestation is accepted until a real fixture is committed";

    public static final int SIGNATURE_SIZE = 256;
    static final int FW2_ATTRIBUTE_OFFSET = 20;
    /** Bounds the attribute walk; a real key carries a few dozen attributes. */
    static final int MAX_ATTRIBUTES = 512;
    /** Bounds gzip expansion of a submitted attestation. */
    static final int MAX_DECOMPRESSED_SIZE = 1 << 20;

    public static final int ATTR_CLASS = 0x0000;
    public static final int ATTR_KEY_TYPE = 0x0100;
    public static final int ATTR_ID = 0x0102;
    public static final int ATTR_MODULUS = 0x0120;
    public static final int ATTR_PUBLIC_EXPONENT = 0x0122;
    public static final int ATTR_EXTRACTABLE = 0x0162;
    public static final int ATTR_LOCAL = 0x0163;
    public static final int ATTR_NEVER_EXTRACTABLE = 0x0164;

    public static final long CKO_PUBLIC_KEY = 2;
    public static final long CKO_PRIVATE_KEY = 3;
    public static final long CKK_RSA = 0;

    /**
     * Marvell LiquidSecurity root, reissued 2024-07-25 to 2034-07-23 with the
     * same key as the 2015 root this repository pinned before. Copied from
     * {@code MARVELL_HSM_ROOT_CERTIFICATE} in Microsoft's validator.
     * SHA-256 23:01:43:DF:00:E0:B4:52:74:3E:06:8A:5B:3F:C0:8D:F8:F0:6C:EF:C4:85:4E:A6:27:AE:B7:EB:D7:0E:E2:F4
     */
    static final String MARVELL_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDvzCCAqegAwIBAgIBADANBgkqhkiG9w0BAQsFADCBkTELMAkGA1UEBhMCVVMx
            EzARBgNVBAgMCkNhbGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYDVQQK
            DAxDYXZpdW0sIEluYy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYDVQQD
            DCFsb2NhbGNhLmxpcXVpZHNlY3VyaXR5LmNhdml1bS5jb20wHhcNMjQwNzI1MjAy
            OTIwWhcNMzQwNzIzMjAyOTIwWjCBkTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh
            bGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYDVQQKDAxDYXZpdW0sIElu
            Yy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYDVQQDDCFsb2NhbGNhLmxp
            cXVpZHNlY3VyaXR5LmNhdml1bS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
            ggEKAoIBAQDckvqQM4cvZjdyqOLGMTjKJwvfxJOhVqw6pojgUMz10VU7z3CtJrwH
            cESwEDUxUkMxzof55kForURLaVVCjedYauEisnZwwSWkAemp9GREm8iX6BXtoZ8V
            DWoO2H0AJiHCM62qJeZVXhm8A/zWG0PyLrCINH0yz9ah6BcwdsZGLvQvkpUNJhwV
            Mrb9nI9BlRmTWhoot1YSTf7jfibEkc/pN+0Ez30RFaL3MhyIaNJS22+10tny4sOU
            TsPEtXKah5mPlHpnrGcB18z5Yxgr0vDNYx+FCPGo95XGrq9NYfNMlwsSeFSr8D1V
            Q7HZmipeTB1hQTUQw/K/Rmtw5NiljkYTAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIC
            hDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCYlr7aeTnbRfPJGc5Q
            5LEVreY91mp0e5KN331iG3DXQ6x07RMY4PPN+MvVgIPD21Ix6Xtp6Vj9VcsBpV7h
            +6X69s79Ix8j0XV+6+AnrLuftjUjNw7iI9shOYa9aSTg/R6YpwwpXH+L3SZZ+VEF
            yBg5gM7az0aJvuF48fSxNNwel11VC6xkrUFTuzI13GqYe+2rWhc/4TWvs1PpSzA0
            K0W7KYFX2jhGi7H1uOrVneJiaVgD9bgIao/UaQabjlLT62wE9DegpdKPOHbIiQp5
            XOV1rIP/pAWSSiyY7BB7c1acC/3ucDoSjTNUEsVIk3Zsm2jiUy0XC/rZTxaZkHaH
            Bux7
            -----END CERTIFICATE-----""";

    /**
     * Marvell LiquidSecurity 2 root, 2024-07-22 to 2034-07-20. Copied from
     * {@code MARVELL_LS2_HSM_ROOT_CERTIFICATE} in Microsoft's validator.
     * SHA-256 17:64:4D:E0:D3:3B:C7:3B:2F:4E:F4:C2:0A:11:F6:C8:CC:1F:72:3A:4C:D8:3E:E6:00:36:1C:BB:24:D8:D2:E5
     */
    static final String MARVELL_LS2_ROOT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIFbTCCA1WgAwIBAgIBADANBgkqhkiG9w0BAQsFADBpMUMwCQYDVQQGEwJVUzAJ
            BgNVBAgMAkNBMAsGA1UECwwEU1NCVTAOBgNVBAcMB1Nhbkpvc2UwDgYDVQQKDAdN
            YXJ2ZWxsMSIwIAYDVQQDDBljYXZpdW0tbGlxdWlkc2VjdXJpdHktbHMyMB4XDTI0
            MDcyMjIwMzQyM1oXDTM0MDcyMDIwMzQyM1owaTFDMAkGA1UEBhMCVVMwCQYDVQQI
            DAJDQTALBgNVBAsMBFNTQlUwDgYDVQQHDAdTYW5Kb3NlMA4GA1UECgwHTWFydmVs
            bDEiMCAGA1UEAwwZY2F2aXVtLWxpcXVpZHNlY3VyaXR5LWxzMjCCAiIwDQYJKoZI
            hvcNAQEBBQADggIPADCCAgoCggIBAM8x8JJPLiULUzlmnDKTQpFvg0iy5Gajj7Vt
            OU04sszOVxcFWM4aUIhGxq7bbKtX7SxMiuR7wfSIkTW+O5AR3kG+PxhPKycfKaAS
            0HTO38eRmI1q94E26g/kn4+6H8ECWOcRm1UxNljEJNsHc6NCw3NotVFfefvEYgpj
            2NS5RGcWs9IcPhXfz7uEdA60taEdyhvqetoPQoYUKFpWB3uuhOXuYUuNyiXqDem6
            QLG1zlc7da9tZ9H/xZZUwfhPxDYhi7j6PQbgbookN/csVC29tNitTZ8CKFPxLoGD
            JMKCoV87Kn9Uce8Q6+6x7uGvngpJuzTksX7F69hEPA+qwmPu5+NczaxNHtgffcsM
            +1Yoz0HJF7EQwXb8eST729Y7KHOF/rMOv3pCpKVIVpMrlfPZrIsf8pEMDKGKyHnZ
            27Vyd1YwkHGLpw5oEsbctlzz0YbKntj5srToQflRj/8Gb27W4SgFJ8FpaTnNnHrE
            SUKrXgFgfShA7wOZbdPzgNbRD1kdeptqypwXYr2OGlqidWRFtoQsLjmy+DO7/Y8T
            0KzI5WpNpS2fxP/JlW070mCW0BmvMZBy9QarJjhwOWKD2lRqDWCkguRJpjKnLBUU
            jjnBWQuJnFYcLuM1IGvIBhRyMuvsuv+iwNwabIaAffb55NK52jR695XN53/VqrW/
            GGXVRbXbAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIChDAMBgNVHRMEBTADAQH/MA0G
            CSqGSIb3DQEBCwUAA4ICAQCNdyJeWTIyOQ6mymRYta5tXfzIdBUT01RYSkLmsCga
            sLbSHAZlq8HOwmozEr8ZL39f2BQ798VFHvHwsjJJVbJNY6Y9CmXehssPWxFlNYTX
            j4P4GIevp19St9VU1d9alThYDyP7ZHTZhMoqlZfvqYQ6pzdvI+R+9vhHumENn8Nm
            0HBz7lwc0rwM1LpnfqD2k/dmCk1x943e5o+Rzi7kYzm4+gjtaEftbvTX5FZ/jTpv
            dOOkGv50kn37JHaR/+FJwEmYQEbst7hVykyQO/FJ0wtkFkjNDpPqQyTeuWpAeTn8
            xYe8zZ8UGiolqFGJO2SimLITCsbofoEUnnYr4Hp7z4N1vZIbg65GvVTdo8be8IDz
            AKrK3fMOT+zsKjaGPhVCvMObfu3w+yQ6Xon8850BXIkQbizuLprEW/TwhTMAta4N
            1c5rGEQf7Ew0NuO3kGyANWub63ZzAMaLCJ8hRKh6VdbtF16E/ShjmbvXXV6O0Sg5
            B81l7Hads8Z/DWNTYpqyt4MqW0429+31VwZle4yryV8bfsRi7Yj7Y0FUxCQYeNc0
            zJ+6GDHbEW5D+DB2S7Kyd4IK2WEg6HJZWS2EM6+oVEO9dBgKOAVMZL74ozlhRS7m
            783mhtSNzDnJe2DHaTofytCJFWeIntMvl7KWljI9LBaJ3PczFfg2b0IbkFE/hMJI
            sA==
            -----END CERTIFICATE-----""";

    private MarvellAttestation() {
    }

    /** The Marvell roots a manufacturer chain may start from. */
    public static List<X509Certificate> marvellRoots() {
        return List.of(certificate(MARVELL_ROOT_PEM), certificate(MARVELL_LS2_ROOT_PEM));
    }

    static X509Certificate certificate(String pem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(pem.trim().getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException("Pinned certificate does not parse", e);
        }
    }

    /** Which layout a blob parsed as. */
    public enum Layout {
        FIRMWARE_2X, FIRMWARE_3X
    }

    /** A strictly parsed attestation. */
    public record Parsed(Layout layout, Map<Integer, byte[]> attributes, byte[] signedData, byte[] signature) {

        public byte[] attribute(int type) {
            byte[] v = attributes.get(type);
            return v == null ? null : v.clone();
        }

        /** Big-endian unsigned value of a numeric attribute, or null when absent or empty. */
        public BigInteger number(int type) {
            byte[] v = attributes.get(type);
            return v == null || v.length == 0 ? null : new BigInteger(1, v);
        }

        /** {@code TRUE} or {@code FALSE} for a one-byte 0x01 or 0x00 attribute, null otherwise. */
        public Boolean flag(int type) {
            byte[] v = attributes.get(type);
            if (v == null || v.length != 1 || (v[0] != 0 && v[0] != 1)) {
                return null;
            }
            return v[0] == 1;
        }

        /** {@code OBJ_ATTR_ID} as text, NUL padding removed, as Microsoft's parser reads it. */
        public String id() {
            byte[] v = attributes.get(ATTR_ID);
            return v == null ? null : new String(v, StandardCharsets.UTF_8).replace("\0", "");
        }
    }

    /** Decompresses a gzip container (Google's {@code attestation.dat}); other input is returned as is. */
    public static byte[] gunzipIfCompressed(byte[] in) throws IOException {
        if (in.length < 2 || (in[0] & 0xFF) != 0x1F || (in[1] & 0xFF) != 0x8B) {
            return in;
        }
        try (InputStream gz = new GZIPInputStream(new ByteArrayInputStream(in))) {
            byte[] out = gz.readNBytes(MAX_DECOMPRESSED_SIZE + 1);
            if (out.length > MAX_DECOMPRESSED_SIZE) {
                throw new IOException("Decompressed attestation exceeds " + MAX_DECOMPRESSED_SIZE + " bytes");
            }
            return out;
        }
    }

    /**
     * Parses both layouts strictly inside the signed data and returns the one
     * that fits.
     *
     * @throws IllegalArgumentException when the blob fits neither layout or both
     */
    public static Parsed parse(byte[] blob) {
        if (blob == null || blob.length <= SIGNATURE_SIZE) {
            throw new IllegalArgumentException("Attestation is shorter than its " + SIGNATURE_SIZE + "-byte signature");
        }
        byte[] data = Arrays.copyOf(blob, blob.length - SIGNATURE_SIZE);
        byte[] sig = Arrays.copyOfRange(blob, blob.length - SIGNATURE_SIZE, blob.length);

        Map<Integer, byte[]> fw2 = tryParse(() -> attributesAt(data, FW2_ATTRIBUTE_OFFSET));
        Map<Integer, byte[]> fw3 = tryParse(() -> fw3Attributes(blob, data));
        if (fw2 != null && fw3 != null) {
            throw new IllegalArgumentException("Attestation parses as both firmware 2.x and 3.x; layout is ambiguous");
        }
        if (fw2 == null && fw3 == null) {
            throw new IllegalArgumentException("Attestation parses as neither firmware 2.x nor 3.x");
        }
        return fw2 != null
                ? new Parsed(Layout.FIRMWARE_2X, fw2, data, sig)
                : new Parsed(Layout.FIRMWARE_3X, fw3, data, sig);
    }

    private interface AttributeParse {
        Map<Integer, byte[]> run();
    }

    private static Map<Integer, byte[]> tryParse(AttributeParse p) {
        try {
            return p.run();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Map<Integer, byte[]> fw3Attributes(byte[] blob, byte[] data) {
        ByteBuffer b = ByteBuffer.wrap(blob);
        long total = u32(b, 8);
        long buffer = u32(b, 12);
        long infoOffset = total - (buffer + SIGNATURE_SIZE);
        if (infoOffset < 0 || infoOffset + 8 > data.length) {
            throw new IllegalArgumentException("info header outside the signed data");
        }
        int listOffset = (int) infoOffset + u16(ByteBuffer.wrap(data), (int) infoOffset + 4);
        return attributesAt(data, listOffset);
    }

    /** Walks one {@code >III} header and its {@code >II} records; every byte read must lie in {@code data}. */
    static Map<Integer, byte[]> attributesAt(byte[] data, int offset) {
        ByteBuffer b = ByteBuffer.wrap(data);
        long count = u32(b, offset + 4);
        if (count == 0 || count > MAX_ATTRIBUTES) {
            throw new IllegalArgumentException("attribute count " + count + " out of range");
        }
        int pos = offset + 12;
        Map<Integer, byte[]> attributes = new LinkedHashMap<>();
        for (long i = 0; i < count; i++) {
            long type = u32(b, pos);
            long len = u32(b, pos + 4);
            pos += 8;
            if (type > Integer.MAX_VALUE || len > data.length - pos) {
                throw new IllegalArgumentException("attribute record runs past the signed data");
            }
            if (attributes.put((int) type, Arrays.copyOfRange(data, pos, pos + (int) len)) != null) {
                throw new IllegalArgumentException("attribute 0x" + Long.toHexString(type) + " appears twice");
            }
            pos += (int) len;
        }
        return Collections.unmodifiableMap(attributes);
    }

    private static long u32(ByteBuffer b, int at) {
        if (at < 0 || at + 4 > b.limit()) {
            throw new IllegalArgumentException("read past end");
        }
        return Integer.toUnsignedLong(b.getInt(at));
    }

    private static int u16(ByteBuffer b, int at) {
        if (at < 0 || at + 2 > b.limit()) {
            throw new IllegalArgumentException("read past end");
        }
        return Short.toUnsignedInt(b.getShort(at));
    }

    /**
     * Whether {@code cert}'s key signed {@code parsed}, under the scheme its
     * layout uses: PKCS#1 v1.5 for firmware 3.x, Microsoft's raw trailing-hash
     * comparison for firmware 2.x (exponent at least 65537).
     */
    public static boolean signedBy(Parsed parsed, X509Certificate cert) {
        if (!(cert.getPublicKey() instanceof RSAPublicKey key)) {
            return false;
        }
        return parsed.layout() == Layout.FIRMWARE_3X
                ? pkcs1(parsed, key, digestOf(cert))
                : rawTrailingHash(parsed, key);
    }

    /** Whether {@code cert}'s key signed {@code parsed} with SHA-256 PKCS#1 v1.5, as Google's tool checks it. */
    public static boolean signedPkcs1Sha256(Parsed parsed, X509Certificate cert) {
        return cert.getPublicKey() instanceof RSAPublicKey key && pkcs1(parsed, key, "SHA256withRSA");
    }

    private static String digestOf(X509Certificate cert) {
        String alg = cert.getSigAlgName().toUpperCase();
        if (alg.startsWith("SHA384")) {
            return "SHA384withRSA";
        }
        if (alg.startsWith("SHA512")) {
            return "SHA512withRSA";
        }
        return "SHA256withRSA";
    }

    private static boolean pkcs1(Parsed parsed, PublicKey key, String algorithm) {
        try {
            Signature s = Signature.getInstance(algorithm);
            s.initVerify(key);
            s.update(parsed.signedData());
            return s.verify(parsed.signature());
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean rawTrailingHash(Parsed parsed, RSAPublicKey key) {
        if (key.getPublicExponent().compareTo(BigInteger.valueOf(65537)) < 0) {
            return false;
        }
        BigInteger s = new BigInteger(1, parsed.signature());
        if (s.signum() == 0 || s.compareTo(key.getModulus()) >= 0) {
            return false;
        }
        byte[] m = s.modPow(key.getPublicExponent(), key.getModulus()).toByteArray();
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(parsed.signedData());
            return m.length >= hash.length
                    && MessageDigest.isEqual(Arrays.copyOfRange(m, m.length - hash.length, m.length), hash);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * What a verified private-key attestation, and optionally a verified
     * public-key attestation of the same key, say about the key.
     *
     * @param extractable    true unless EXTRACTABLE is false and NEVER_EXTRACTABLE is true
     * @param keyOrigin      {@code generated} when LOCAL and NEVER_EXTRACTABLE are both true,
     *                       otherwise {@code unverified}
     * @param publicKeyMatch the attested modulus and exponent equal the CSR's RSA key
     */
    public record KeyEvidence(boolean extractable, String keyOrigin, boolean publicKeyMatch,
                              String keyId, int keyBits, List<String> errors) {
    }

    /**
     * Reads key evidence from attestations whose signatures and chains the
     * caller has already verified. Every attribute must be present with a
     * well-formed value; a missing attribute counts against the key.
     *
     * @param privateKey the private-key attestation
     * @param publicKey  the public-key attestation of the same key, or null
     */
    public static KeyEvidence evaluate(Parsed privateKey, Parsed publicKey, PublicKey csrKey) {
        List<String> errors = new ArrayList<>();

        if (!Long.valueOf(CKO_PRIVATE_KEY).equals(longOrNull(privateKey.number(ATTR_CLASS)))) {
            errors.add("MARVELL_NOT_A_PRIVATE_KEY_ATTESTATION: OBJ_ATTR_CLASS is not CKO_PRIVATE_KEY");
        }
        if (!Long.valueOf(CKK_RSA).equals(longOrNull(privateKey.number(ATTR_KEY_TYPE)))) {
            errors.add("MARVELL_KEY_NOT_RSA: OBJ_ATTR_KEY_TYPE is not CKK_RSA");
        }
        Boolean extractableFlag = privateKey.flag(ATTR_EXTRACTABLE);
        Boolean neverExtractable = privateKey.flag(ATTR_NEVER_EXTRACTABLE);
        Boolean local = privateKey.flag(ATTR_LOCAL);
        boolean extractable = !(Boolean.FALSE.equals(extractableFlag) && Boolean.TRUE.equals(neverExtractable));
        if (extractable) {
            errors.add("MARVELL_KEY_EXTRACTABLE: OBJ_ATTR_EXTRACTABLE=" + extractableFlag
                    + ", OBJ_ATTR_NEVER_EXTRACTABLE=" + neverExtractable
                    + " (required: false and true)");
        }
        boolean generated = Boolean.TRUE.equals(local) && Boolean.TRUE.equals(neverExtractable);
        if (!generated) {
            errors.add("MARVELL_KEY_NOT_GENERATED: OBJ_ATTR_LOCAL=" + local
                    + ", OBJ_ATTR_NEVER_EXTRACTABLE=" + neverExtractable
                    + " (required: true and true)");
        }

        if (publicKey != null) {
            if (!Long.valueOf(CKO_PUBLIC_KEY).equals(longOrNull(publicKey.number(ATTR_CLASS)))) {
                errors.add("MARVELL_NOT_A_PUBLIC_KEY_ATTESTATION: OBJ_ATTR_CLASS is not CKO_PUBLIC_KEY");
            }
            String privateId = privateKey.id();
            if (privateId == null || !privateId.equals(publicKey.id())) {
                errors.add("MARVELL_ATTESTATIONS_DIFFER: the public- and private-key attestations "
                        + "carry different OBJ_ATTR_ID values");
            }
        }

        BigInteger modulus = null;
        BigInteger exponent = null;
        for (Parsed p : publicKey == null ? List.of(privateKey) : List.of(privateKey, publicKey)) {
            BigInteger n = p.number(ATTR_MODULUS);
            BigInteger e = p.number(ATTR_PUBLIC_EXPONENT);
            if (n == null || e == null) {
                continue;
            }
            if (modulus != null && (!modulus.equals(n) || !exponent.equals(e))) {
                errors.add("MARVELL_ATTESTATIONS_DIFFER: the attestations carry different RSA keys");
                modulus = null;
                break;
            }
            modulus = n;
            exponent = e;
        }

        boolean match = false;
        if (modulus == null) {
            errors.add("MARVELL_KEY_NOT_BOUND: no attestation carries both the modulus (0x0120) and "
                    + "the public exponent (0x0122), so the attestation cannot be tied to the CSR key");
        } else if (csrKey instanceof RSAPublicKey rsa
                && rsa.getModulus().equals(modulus) && rsa.getPublicExponent().equals(exponent)) {
            match = true;
        } else {
            errors.add("MARVELL_PUBLIC_KEY_MISMATCH: the attested RSA key is not the CSR key");
        }

        return new KeyEvidence(extractable, generated ? "generated" : "unverified", match,
                privateKey.id(), modulus == null ? 0 : modulus.bitLength(), List.copyOf(errors));
    }

    private static Long longOrNull(BigInteger v) {
        return v == null || v.bitLength() > 63 ? null : v.longValue();
    }

    /** Manufacturer chain found in a bundle: Marvell root, the card certificate it issued, and the partition certificate. */
    public record ManufacturerChain(X509Certificate root, X509Certificate card, X509Certificate partition) {
    }

    /**
     * Finds root → card → partition the way both vendor tools do: by issuer
     * name and signature, starting from one of {@code roots}.
     *
     * @return the chain, or null when the bundle holds none
     */
    public static ManufacturerChain manufacturerChain(List<X509Certificate> bundle, List<X509Certificate> roots) {
        for (X509Certificate root : roots) {
            for (X509Certificate card : issuedBy(root, bundle)) {
                for (X509Certificate partition : issuedBy(card, bundle)) {
                    return new ManufacturerChain(root, card, partition);
                }
            }
        }
        return null;
    }

    /** Certificates in {@code bundle}, other than {@code issuer} itself, that {@code issuer} signed. */
    public static List<X509Certificate> issuedBy(X509Certificate issuer, List<X509Certificate> bundle) {
        List<X509Certificate> out = new ArrayList<>();
        for (X509Certificate c : bundle) {
            if (c.equals(issuer) || !c.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                continue;
            }
            try {
                c.verify(issuer.getPublicKey());
                out.add(c);
            } catch (Exception ignored) {
                // not issued by this certificate
            }
        }
        return out;
    }

    /** Parses one or more concatenated PEM certificates. */
    public static List<X509Certificate> parsePemBundle(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> out = new ArrayList<>();
        for (var c : cf.generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))) {
            out.add((X509Certificate) c);
        }
        return out;
    }

    /** Hex for diagnostics. */
    static String hex(byte[] b) {
        return b == null ? null : HexFormat.of().formatHex(b);
    }
}
