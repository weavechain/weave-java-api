package com.weavechain.core.encrypt;

import com.weavechain.core.data.ConvertUtils;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class ChaChaPolyFieldEncrypt extends FieldEncrypt {

    static final Logger logger = LoggerFactory.getLogger(ChaChaPolyFieldEncrypt.class);

    private static final String KEY_FACTORY = "PBKDF2WithHmacSHA256";

    private static final String ALGORITHM = "ChaCha20-Poly1305";

    private static final SecureRandom RND = new SecureRandom();

    private SecretKeySpec secretKey;

    private Cipher cipher;

    @Override
    public void init(String key, String salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY);
            KeySpec spec = new PBEKeySpec(key.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            cipher = Cipher.getInstance(ALGORITHM);
        } catch (Exception e) {
            logger.error("Failed encryptor initialization");
        }
    }

    @Override
    public Object encrypt(Object value) {
        if (value != null) {
            try {
                byte[] iv = KeysProvider.generateIV(12);
                IvParameterSpec ivspec = new IvParameterSpec(iv);

                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
                byte[] enc = cipher.doFinal(ConvertUtils.convertToString(value).getBytes(StandardCharsets.UTF_8));

                ByteArrayOutputStream output = new ByteArrayOutputStream();
                output.write(iv);
                output.write(enc);

                return Base64.encodeBase64String(output.toByteArray());
            } catch (Exception e) {
                logger.error("Failed encryption", e);
            }
        }
        return null;
    }

    @Override
    public Object decrypt(Object value) {
        if (value != null) {
            try {
                byte[] input = Base64.decodeBase64(ConvertUtils.convertToString(value).getBytes(StandardCharsets.UTF_8));

                byte[] iv = Arrays.copyOfRange(input, 0, 12);
                IvParameterSpec ivspec = new IvParameterSpec(iv);

                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
                byte[] enc =  Arrays.copyOfRange(input, 12, input.length);
                return new String(cipher.doFinal(enc), StandardCharsets.UTF_8);
            } catch (Exception e) {
                logger.error("Failed decryption", e);
            }
        }
        return null;
    }
}