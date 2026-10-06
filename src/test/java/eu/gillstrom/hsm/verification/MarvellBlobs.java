package eu.gillstrom.hsm.verification;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

/** Builds synthetic Marvell attestations in the two layouts {@link MarvellAttestation} reads. */
final class MarvellBlobs {

    private final Map<Integer, byte[]> attributes = new LinkedHashMap<>();

    static MarvellBlobs privateKey(RSAPublicKey key, String id) {
        return new MarvellBlobs()
                .put(MarvellAttestation.ATTR_CLASS, new byte[] {3})
                .put(MarvellAttestation.ATTR_KEY_TYPE, new byte[] {0})
                .put(MarvellAttestation.ATTR_ID, id.getBytes(StandardCharsets.UTF_8))
                .put(MarvellAttestation.ATTR_MODULUS, unsigned(key.getModulus()))
                .put(MarvellAttestation.ATTR_PUBLIC_EXPONENT, unsigned(key.getPublicExponent()))
                .put(MarvellAttestation.ATTR_EXTRACTABLE, new byte[] {0})
                .put(MarvellAttestation.ATTR_NEVER_EXTRACTABLE, new byte[] {1})
                .put(MarvellAttestation.ATTR_LOCAL, new byte[] {1});
    }

    static MarvellBlobs publicKey(RSAPublicKey key, String id) {
        return new MarvellBlobs()
                .put(MarvellAttestation.ATTR_CLASS, new byte[] {2})
                .put(MarvellAttestation.ATTR_KEY_TYPE, new byte[] {0})
                .put(MarvellAttestation.ATTR_ID, id.getBytes(StandardCharsets.UTF_8))
                .put(MarvellAttestation.ATTR_MODULUS, unsigned(key.getModulus()))
                .put(MarvellAttestation.ATTR_PUBLIC_EXPONENT, unsigned(key.getPublicExponent()));
    }

    MarvellBlobs put(int type, byte[] value) {
        attributes.put(type, value);
        return this;
    }

    MarvellBlobs remove(int type) {
        attributes.remove(type);
        return this;
    }

    /** The attribute list: {@code >III} header and {@code >II} records. */
    byte[] attributeList() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(ByteBuffer.allocate(12).putInt(0).putInt(attributes.size()).putInt(0).array());
        attributes.forEach((type, value) -> {
            out.writeBytes(ByteBuffer.allocate(8).putInt(type).putInt(value.length).array());
            out.writeBytes(value);
        });
        return out.toByteArray();
    }

    /** Firmware 2.x: 20 bytes, then the attribute list. */
    byte[] fw2Data() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[MarvellAttestation.FW2_ATTRIBUTE_OFFSET]);
        out.writeBytes(attributeList());
        return out.toByteArray();
    }

    /** Firmware 3.x: response header, info header at 16, attribute list 8 bytes after it. */
    byte[] fw3Data() {
        byte[] list = attributeList();
        int dataLength = 16 + 8 + list.length;
        int total = dataLength + MarvellAttestation.SIGNATURE_SIZE;
        int buffer = total - MarvellAttestation.SIGNATURE_SIZE - 16;
        ByteBuffer b = ByteBuffer.allocate(dataLength);
        b.putInt(0).putInt(0).putInt(total).putInt(buffer);
        b.putShort((short) 0).putShort((short) 0).putShort((short) 8).putShort((short) 0);
        b.put(list);
        return b.array();
    }

    static byte[] signed(byte[] data, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(data);
        byte[] sig = s.sign();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(data);
        out.writeBytes(sig);
        return out.toByteArray();
    }

    private static byte[] unsigned(BigInteger v) {
        byte[] b = v.toByteArray();
        return b[0] == 0 && b.length > 1 ? java.util.Arrays.copyOfRange(b, 1, b.length) : b;
    }
}
