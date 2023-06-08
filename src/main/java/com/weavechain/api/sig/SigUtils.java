package com.weavechain.api.sig;

import cafe.cryptography.curve25519.Scalar;
import com.weavechain.core.data.Records;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.Hash;
import org.bitcoinj.base.Base58;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

public class SigUtils {

    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    public static SecureRandom random() {
        return RANDOM.get();
    }

    public static Scalar scalarFromBigInteger(BigInteger value) {
        byte[] data = value.toByteArray();
        byte[] dest = new byte[32];
        int start = Math.max(0, data.length - 32);
        for (int j = start; j < data.length; j++) {
            dest[j - start] = data[data.length - 1 + start - j];
        }
        return Scalar.fromBits(dest);
    }

    public static Scalar hashScalar(String text, byte[] challenge) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(text.getBytes(StandardCharsets.UTF_8));
        if (challenge != null) {
            md.update(challenge);
        }

        byte[] digest = md.digest();
        return Scalar.fromBytesModOrderWide(digest);
    }

    public static String encodeForSigning(List<Object> record) {
        return Utils.getListJsonAdapter().toJson(record); //Utils.getGson()
    }

    public static String encodeForSigning(List<Object> row, byte[] challenge, String digest) {
        String encoded = SigUtils.encodeForSigning(row);
        return Base58.encode(Hash.signString(challenge, encoded, digest));
    }

    public static String encodeForSigning(Records records) {
        return Utils.getListJsonAdapter().toJson(records.getItems());
    }

    public static byte[] encodeForSigning(Records data, byte[] challenge, String digest) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        for (List<Object> item : data.getItems()) {
            String encoded = SigUtils.encodeForSigning(item);
            byte[] hash = Hash.signString(challenge, encoded, digest);
            if (hash != null) {
                outputStream.write(hash);
            }
        }

        return outputStream.toByteArray();
    }
}