package com.weavechain.core.encrypt;

import com.swiftcryptollc.crypto.provider.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KyberKeys implements KeyExchange {

    static final Logger logger = LoggerFactory.getLogger(KyberKeys.class);

    private static final String CIPHER = "AES/CBC/PKCS5Padding";

    private static final String ALGORITHM = "Kyber";

    private static final String KEY_PROVIDER = "Kyber1024";

    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    @Override
    public KeyPair readKeys(String encodedPrivateKey, String encodedPublicKey) {
        try {
            PublicKey publicKey = readPublicKey(encodedPublicKey);
            PrivateKey privateKey = readPrivateKey(encodedPrivateKey);

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            logger.error("Failed decoding keys", e);
            return null;
        }
    }

    private PublicKey readPublicKey(String encodedPublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey publicKey = null;

        if (encodedPublicKey != null) {
            encodedPublicKey = encodedPublicKey.replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "");
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Hex.decode(encodedPublicKey));
            publicKey = keyFactory.generatePublic(keySpec);
        }
        return publicKey;
    }

    private PrivateKey readPrivateKey(String encodedPrivateKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PrivateKey privateKey = null;

        if (encodedPrivateKey != null) {
            encodedPrivateKey = encodedPrivateKey.replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "");
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            try {
                byte[] key = Hex.decode(encodedPrivateKey);
                if (key.length > 0) {
                    privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));
                }
            } catch (Exception e) {
                logger.error("Failed reading private key", e);
            }
        }
        return privateKey;
    }

    @Override
    public KeyPair generateKeys() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_PROVIDER);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            logger.error("Failed generating keys", e);
            return null;
        }
    }

    @Override
    public SecretKey sharedSecret(PrivateKey privatekey, PublicKey publicKey, byte[] message) {
        try {
            KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
            keyAgreement.engineInit(privatekey);
            keyAgreement.engineDoPhase(publicKey, true);

            KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_1024, new KyberCipherText(message, null, null));
            KyberSecretKey secretKey = kyberDecrypted.getSecretKey();

            return new SecretKeySpec(secretKey.getS(), ALGORITHM);
        } catch (Exception e) {
            logger.error("Failed generating keys", e);
            return null;
        }
    }

    private byte[] getIV(byte[] seed, byte[] iv) {
        byte[] s = new byte[iv.length];
        for (int i = 0; i < iv.length; i++) {
            s[i] = iv[i];
            s[i] ^= seed[i % seed.length];
        }
        return s;
    }

    @Override
    public byte[] encrypt(SecretKey key, byte[] data, byte[] seed, byte[] iv) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(getIV(seed, iv));
            Cipher cipher = Cipher.getInstance(CIPHER, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] encrypted = new byte[cipher.getOutputSize(data.length)];
            int len = cipher.update(data, 0, data.length, encrypted, 0);
            cipher.doFinal(encrypted, len);
            return encrypted;
        } catch (Exception e) {
            logger.error("Failed encrypt", e);
            return null;
        }
    }

    @Override
    public byte[] decrypt(SecretKey key, byte[] data, byte[] seed, byte[] iv) {
        try {
            Key decryptionKey = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
            IvParameterSpec ivSpec = new IvParameterSpec(getIV(seed, iv));
            Cipher cipher = Cipher.getInstance(CIPHER, PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
            byte[] decrypted = new byte[cipher.getOutputSize(data.length)];
            int len = cipher.update(data, 0, data.length, decrypted, 0);
            cipher.doFinal(decrypted, len);
            return decrypted;
        } catch (Exception e) {
            logger.error("Failed decrypt", e);
            return null;
        }
    }
}
