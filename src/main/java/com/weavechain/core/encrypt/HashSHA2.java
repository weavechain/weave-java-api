package com.weavechain.core.encrypt;

import org.bitcoinj.base.Base58;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashSHA2 implements HashFunction {

    static final Logger logger = LoggerFactory.getLogger(HashSHA2.class);

    @Override
    public byte[] digest(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
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
