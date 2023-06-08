package com.weavechain.api.auth;

import com.weavechain.core.encrypt.KeysProvider;
import com.weavechain.core.encrypt.Seed;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;

@Getter
@AllArgsConstructor
public class Keys {

    private final String seed;

    private final String publicKey;

    private final String privateKey;

    public static Keys generateKeys() {
        return generateKeys(null);
    }

    public static Keys generateKeys(String seed) {
        KeyPair serverKeys = KeysProvider.getInstance().generateKeys();
        String publicKey = KeysProvider.getBase58Key(serverKeys.getPublic());
        String privateKey = KeysProvider.getBase58Key(serverKeys.getPrivate());

        return new Keys(
                seed != null ? seed : Hex.toHexString(Seed.generate()),
                publicKey,
                privateKey
        );
    }

    public static void main(String[] args) {
        KeyPair keys = KeysProvider.getInstance().generateKeys();

        String publicKey = KeysProvider.getBase58Key(keys.getPublic());
        String privateKey = KeysProvider.getBase58Key(keys.getPrivate());

        System.out.println(publicKey);
        System.out.println(privateKey);
    }
}
