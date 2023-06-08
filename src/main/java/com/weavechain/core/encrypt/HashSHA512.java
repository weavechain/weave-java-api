package com.weavechain.core.encrypt;

import org.bitcoinj.base.Base58;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashSHA512 implements HashFunction {

    static final Logger logger = LoggerFactory.getLogger(HashSHA512.class);

    @Override
    public byte[] digest(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(data.getBytes(StandardCharsets.UTF_8));
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed computing hash", e);
            return null;
        }
    }

    @Override
    public String hexDigest(String data) {
        return Hex.toHexString(digest(data));
    }

    @Override
    public String b58Digest(String data) {
        return Base58.encode(digest(data));
    }
}
