package com.weavechain.core.encrypt;

import net.thiim.dilithium.interfaces.DilithiumPublicKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.bitcoinj.base.Base58;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class ECIESKeys implements KeyExchange {

    static final Logger logger = LoggerFactory.getLogger(ECIESKeys.class);

    private static final String CIPHER = "AES/CBC/PKCS5Padding";

    private static final String ALGORITHM = "ECDH";

    private static final String CURVE_TYPE = "secp256k1"; //secp256r1

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

    static byte[] uncompress(byte[] compKey) throws IOException {
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE_TYPE);
        ECPoint point = spec.getCurve().decodePoint(compKey);
        byte[] x = point.getXCoord().getEncoded();
        byte[] y = point.getYCoord().getEncoded();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(0x04);
        outputStream.write(x);
        outputStream.write(y);
        return outputStream.toByteArray();
    }

    private PublicKey readPublicKey(String encodedPublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey publicKey = null;

        if (encodedPublicKey != null) {
            encodedPublicKey = encodedPublicKey.replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "");
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            try {
                if (encodedPublicKey.length() < KeysProvider.MAX_B58_LEN) {
                    byte[] key = Base58.decode(encodedPublicKey.startsWith(KeysProvider.PREFIX) ? encodedPublicKey.substring(KeysProvider.PREFIX.length()) : encodedPublicKey);

                    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE_TYPE);
                    ECPoint pubPoint = spec.getCurve().decodePoint(key);
                    ECPublicKeySpec keySpec = new ECPublicKeySpec(pubPoint, spec);

                    publicKey = keyFactory.generatePublic(keySpec);
                } else {
                    byte[] key = Hex.decode(encodedPublicKey);
                    if (key.length > 0) {
                        publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(key));
                    }
                }
            } catch (Exception e) {
                try {
                    byte[] key = Base58.decode(encodedPublicKey);
                    publicKey = decodeKey(keyFactory, key);
                } catch (Exception ex) {
                    byte[] key = Base64.decodeBase64(encodedPublicKey);
                    publicKey = decodeKey(keyFactory, key);
                }
            }
        }
        return publicKey;
    }

    private PublicKey decodeKey(KeyFactory keyFactory, byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey;
        try {
            publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(key));
        } catch (InvalidKeySpecException e) {
            try {
                KeyFactory kf = KeyFactory.getInstance("EdDSA");
                publicKey = kf.generatePublic(new X509EncodedKeySpec(key));
            } catch (InvalidKeySpecException ex) {
                KeyFactory kf = KeyFactory.getInstance("Dilithium");
                publicKey = kf.generatePublic(new DilithiumPublicKeySpec(KeysProvider.DILITHIUM_PARAM_SPEC, key));
            }
        }
        return publicKey;
    }

    private PrivateKey readPrivateKey(String encodedPrivateKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PrivateKey privateKey = null;

        if (encodedPrivateKey != null) {
            encodedPrivateKey = encodedPrivateKey.replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "");
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            try {
                if (encodedPrivateKey.length() < KeysProvider.MAX_B58_LEN) {
                    byte[] key = Base58.decode(encodedPrivateKey);

                    BigInteger d = new BigInteger(1, key.length == 33 ? Arrays.copyOfRange(key, 1, key.length) : key);
                    ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(CURVE_TYPE);
                    ECPrivateKeySpec keySpec = new ECPrivateKeySpec(d, params);

                    return keyFactory.generatePrivate(keySpec);
                } else {
                    byte[] key = Hex.decode(encodedPrivateKey);
                    if (key.length > 0) {
                        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));
                    }
                }
            } catch (Exception e) {
                byte[] key = Base64.decodeBase64(encodedPrivateKey);
                try {
                    privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));
                } catch (InvalidKeySpecException ex) {
                    KeyFactory kf = KeyFactory.getInstance("EdDSA");
                    privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(key));
                }
            }
        }
        return privateKey;
    }

    @Override
    public KeyPair generateKeys() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
            kpg.initialize(new ECGenParameterSpec(CURVE_TYPE));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            logger.error("Failed generating keys", e);
            return null;
        }
    }

    @Override
    public SecretKey sharedSecret(PrivateKey privateKey, PublicKey publicKey, byte[] message) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM, PROVIDER);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret("AES");
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
