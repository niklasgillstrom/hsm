package eu.gillstrom.hsm.verification;

import eu.gillstrom.hsm.testsupport.TestPki;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MarvellAttestationTest {

    private static KeyPair hsmKey;
    private static KeyPair partitionKp;
    private static X509Certificate partition;

    @BeforeAll
    static void keys() throws Exception {
        hsmKey = TestPki.newRsaKeyPair(2048);
        partitionKp = TestPki.newRsaKeyPair(2048);
        partition = TestPki.selfSignedCa(partitionKp, "TEST-PARTITION");
    }

    private static RSAPublicKey key() {
        return (RSAPublicKey) hsmKey.getPublic();
    }

    @Test
    @DisplayName("The pinned Marvell roots are the certificates in Microsoft's validator")
    void pinnedRootsAreTheVendorsCertificates() throws Exception {
        assertThat(MarvellAttestation.marvellRoots()).extracting(MarvellAttestationTest::sha256).containsExactly(
                "230143df00e0b452743e068a5b3fc08df8f06cefc4854ea627aeb7ebd70ee2f4",
                "17644de0d33bc73b2f4ef4c20a11f6c8cc1f723a4cd83ee600361cbb24d8d2e5");
    }

    @Test
    @DisplayName("Firmware 2.x and 3.x layouts parse to the same attributes")
    void bothLayoutsParse() throws Exception {
        MarvellBlobs b = MarvellBlobs.privateKey(key(), "keys/k/1");

        MarvellAttestation.Parsed fw2 = MarvellAttestation.parse(MarvellBlobs.signed(b.fw2Data(), partitionKp.getPrivate()));
        MarvellAttestation.Parsed fw3 = MarvellAttestation.parse(MarvellBlobs.signed(b.fw3Data(), partitionKp.getPrivate()));

        assertThat(fw2.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_2X);
        assertThat(fw3.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_3X);
        assertThat(fw2.attributes().keySet()).isEqualTo(fw3.attributes().keySet());
        assertThat(fw3.id()).isEqualTo("keys/k/1");
        assertThat(fw3.number(MarvellAttestation.ATTR_MODULUS)).isEqualTo(key().getModulus());
        assertThat(MarvellAttestation.signedBy(fw2, partition)).isTrue();
        assertThat(MarvellAttestation.signedBy(fw3, partition)).isTrue();
    }

    @Test
    @DisplayName("A record that runs into the signature, a huge count or a repeated attribute is rejected")
    void malformedListsAreRejected() throws Exception {
        byte[] overrun = MarvellBlobs.signed(MarvellBlobs.privateKey(key(), "k").fw2Data(), partitionKp.getPrivate());
        // Last record's length now reaches into the signature.
        int lastLen = overrun.length - MarvellAttestation.SIGNATURE_SIZE - 1 - 4;
        ByteBuffer.wrap(overrun).putInt(lastLen, 2);
        assertThatThrownBy(() -> MarvellAttestation.parse(overrun)).isInstanceOf(IllegalArgumentException.class);

        byte[] huge = MarvellBlobs.signed(MarvellBlobs.privateKey(key(), "k").fw2Data(), partitionKp.getPrivate());
        ByteBuffer.wrap(huge).putInt(MarvellAttestation.FW2_ATTRIBUTE_OFFSET + 4, 0x7FFFFFFF);
        assertThatThrownBy(() -> MarvellAttestation.parse(huge)).isInstanceOf(IllegalArgumentException.class);

        ByteArrayOutputStream dup = new ByteArrayOutputStream();
        dup.writeBytes(new byte[MarvellAttestation.FW2_ATTRIBUTE_OFFSET]);
        dup.writeBytes(ByteBuffer.allocate(12).putInt(0).putInt(2).putInt(0).array());
        for (int i = 0; i < 2; i++) {
            dup.writeBytes(ByteBuffer.allocate(9).putInt(MarvellAttestation.ATTR_EXTRACTABLE).putInt(1).put((byte) i).array());
        }
        byte[] twice = MarvellBlobs.signed(dup.toByteArray(), partitionKp.getPrivate());
        assertThatThrownBy(() -> MarvellAttestation.parse(twice)).isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> MarvellAttestation.parse(new byte[256])).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Firmware 2.x raw check: a cube-root forgery under e = 3 is refused")
    void smallExponentForgeryIsRefused() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F0));
        KeyPair e3 = g.generateKeyPair();
        X509Certificate e3Partition = TestPki.selfSignedCa(e3, "E3-PARTITION");

        byte[] data = MarvellBlobs.privateKey(key(), "k").fw2Data();
        byte[] hash;
        do {
            data[0]++;
            hash = MessageDigest.getInstance("SHA-256").digest(data);
        } while ((hash[hash.length - 1] & 1) == 0);
        BigInteger mod256 = BigInteger.ONE.shiftLeft(256);
        BigInteger h = new BigInteger(1, hash);
        BigInteger s = BigInteger.ONE;
        for (int k = 1; k < 256; k++) {
            if (!s.pow(3).subtract(h).mod(BigInteger.ONE.shiftLeft(k + 1)).equals(BigInteger.ZERO)) {
                s = s.setBit(k);
            }
        }
        // The forgery satisfies Microsoft's trailing-hash comparison without the private key.
        RSAPublicKey pub = (RSAPublicKey) e3.getPublic();
        BigInteger raised = s.modPow(pub.getPublicExponent(), pub.getModulus());
        assertThat(raised.mod(mod256)).isEqualTo(h);

        byte[] sig = new byte[MarvellAttestation.SIGNATURE_SIZE];
        byte[] sb = s.toByteArray();
        System.arraycopy(sb, 0, sig, sig.length - sb.length, sb.length);
        byte[] blob = Arrays.copyOf(data, data.length + sig.length);
        System.arraycopy(sig, 0, blob, data.length, sig.length);

        MarvellAttestation.Parsed parsed = MarvellAttestation.parse(blob);
        assertThat(parsed.layout()).isEqualTo(MarvellAttestation.Layout.FIRMWARE_2X);
        assertThat(MarvellAttestation.signedBy(parsed, e3Partition)).isFalse();
    }

    @Test
    @DisplayName("Generated, never-extractable RSA key that is the CSR key gives clean evidence")
    void cleanEvidence() throws Exception {
        MarvellAttestation.KeyEvidence e = evaluate(MarvellBlobs.privateKey(key(), "keys/k/1"), null);

        assertThat(e.errors()).isEmpty();
        assertThat(e.publicKeyMatch()).isTrue();
        assertThat(e.extractable()).isFalse();
        assertThat(e.keyOrigin()).isEqualTo("generated");
        assertThat(e.keyBits()).isEqualTo(2048);
    }

    @Test
    @DisplayName("Extractable, imported or unflagged keys are refused")
    void attributesCountAgainstTheKey() throws Exception {
        assertThat(evaluate(MarvellBlobs.privateKey(key(), "k")
                .put(MarvellAttestation.ATTR_EXTRACTABLE, new byte[] {1}), null).errors())
                .anyMatch(s -> s.startsWith("MARVELL_KEY_EXTRACTABLE"));
        assertThat(evaluate(MarvellBlobs.privateKey(key(), "k")
                .put(MarvellAttestation.ATTR_LOCAL, new byte[] {0}), null).errors())
                .anyMatch(s -> s.startsWith("MARVELL_KEY_NOT_GENERATED"));
        MarvellAttestation.KeyEvidence missing = evaluate(MarvellBlobs.privateKey(key(), "k")
                .remove(MarvellAttestation.ATTR_NEVER_EXTRACTABLE), null);
        assertThat(missing.extractable()).isTrue();
        assertThat(missing.keyOrigin()).isEqualTo("unverified");
        assertThat(evaluate(MarvellBlobs.privateKey(key(), "k")
                .put(MarvellAttestation.ATTR_CLASS, new byte[] {2}), null).errors())
                .anyMatch(s -> s.startsWith("MARVELL_NOT_A_PRIVATE_KEY_ATTESTATION"));
    }

    @Test
    @DisplayName("Without an attested modulus, or with another key's, nothing binds to the CSR")
    void keyBinding() throws Exception {
        assertThat(evaluate(MarvellBlobs.privateKey(key(), "k").remove(MarvellAttestation.ATTR_MODULUS), null).errors())
                .anyMatch(s -> s.startsWith("MARVELL_KEY_NOT_BOUND"));

        RSAPublicKey other = (RSAPublicKey) TestPki.newRsaKeyPair(2048).getPublic();
        MarvellAttestation.KeyEvidence e = evaluate(MarvellBlobs.privateKey(other, "k"), null);
        assertThat(e.publicKeyMatch()).isFalse();
        assertThat(e.errors()).anyMatch(s -> s.startsWith("MARVELL_PUBLIC_KEY_MISMATCH"));
    }

    @Test
    @DisplayName("A public-key attestation of another key object is refused")
    void publicAttestationMustBeTheSameKey() throws Exception {
        MarvellAttestation.KeyEvidence e = evaluate(
                MarvellBlobs.privateKey(key(), "keys/k/1").remove(MarvellAttestation.ATTR_MODULUS),
                MarvellBlobs.publicKey(key(), "keys/other/1"));
        assertThat(e.errors()).anyMatch(s -> s.startsWith("MARVELL_ATTESTATIONS_DIFFER"));

        MarvellAttestation.KeyEvidence ok = evaluate(
                MarvellBlobs.privateKey(key(), "keys/k/1").remove(MarvellAttestation.ATTR_MODULUS),
                MarvellBlobs.publicKey(key(), "keys/k/1"));
        assertThat(ok.errors()).isEmpty();
        assertThat(ok.publicKeyMatch()).isTrue();
    }

    @Test
    @DisplayName("gzip input is decompressed with a size bound")
    void gzipIsBounded() throws Exception {
        ByteArrayOutputStream bomb = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bomb)) {
            gz.write(new byte[MarvellAttestation.MAX_DECOMPRESSED_SIZE + 1]);
        }
        assertThatThrownBy(() -> MarvellAttestation.gunzipIfCompressed(bomb.toByteArray()))
                .hasMessageContaining("exceeds");
    }

    private static MarvellAttestation.KeyEvidence evaluate(MarvellBlobs priv, MarvellBlobs pub) throws Exception {
        MarvellAttestation.Parsed p = MarvellAttestation.parse(MarvellBlobs.signed(priv.fw3Data(), partitionKp.getPrivate()));
        MarvellAttestation.Parsed q = pub == null ? null
                : MarvellAttestation.parse(MarvellBlobs.signed(pub.fw3Data(), partitionKp.getPrivate()));
        return MarvellAttestation.evaluate(p, q, hsmKey.getPublic());
    }

    static String sha256(X509Certificate c) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
