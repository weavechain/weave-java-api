package com.weavechain.core.encrypt;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyExchange {

    KeyPair readKeys(String encodedPrivateKey, String encodedPublicKey);

    KeyPair generateKeys();

    SecretKey sharedSecret(PrivateKey privateKey, PublicKey publicKey, byte[] message);

    byte[] encrypt(SecretKey key, byte[] data, byte[] seed, byte[] iv);

    byte[] decrypt(SecretKey key, byte[] data, byte[] seed, byte[] iv);
}
