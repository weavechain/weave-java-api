package com.weavechain.core.encrypt;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.security.KeyPair;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class KeysInfo {

    private final String encodedPublicKey;

    private final String encodedPrivateKey;

    private final KeyPair keyPair;

    public static KeysInfo fromPublicKey(String encodedPublicKey) {
        KeyExchange keyExchange = KeysProvider.getInstance();
        KeyPair serverKeys = keyExchange.readKeys(null, encodedPublicKey);

        return new KeysInfo(
                encodedPublicKey,
                null,
                serverKeys
        );
    }

    //TODO: drop encodedPublicKey, it's superfluous. For now it's here as we already have it encoded and it's "ok" to have it in plaintext ready to copy/paste
    public static KeysInfo fromEncodedKeyPair(String encodedPrivateKey, String encodedPublicKey) {
        KeyExchange keyExchange = KeysProvider.getInstance();
        KeyPair keyPair = keyExchange.readKeys(encodedPrivateKey, encodedPublicKey);

        return fromKeyPair(keyPair);
    }

    public static KeysInfo fromKeyPair(KeyPair keyPair) {
        return new KeysInfo(
                keyPair.getPublic() != null ? KeysProvider.getBase58Key(keyPair.getPublic()) : null,
                keyPair.getPrivate() != null ? KeysProvider.getBase58Key(keyPair.getPrivate()) : null,
                keyPair
        );
    }
}
