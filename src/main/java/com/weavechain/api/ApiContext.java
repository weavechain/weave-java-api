package com.weavechain.api;

import com.weavechain.core.encrypt.KeysInfo;
import com.weavechain.core.encrypt.KeysProvider;
import lombok.Getter;
import org.bouncycastle.util.encoders.Hex;

import java.security.PrivateKey;
import java.security.PublicKey;

@Getter
public class ApiContext {

    private final KeysInfo clientKey;

    private byte[] seed;

    private String seedHex;

    private KeysInfo serverKey;

    private KeysInfo sigKey;

    private final boolean isDataIntegrityCheck;

    private PrivateKey sigPrivateKey;

    private final boolean isThresholdSigCheck;

    /** if isDataIntegrityCheck = true then used to sign the hash of records before sending,
     *  so data integrity can be checked on receiver side */
    private PrivateKey edPrivateKey;

    public ApiContext(KeysInfo clientKey, byte[] seed, KeysInfo serverKey, KeysInfo sigKey, Boolean isDataIntegrityCheck, Boolean isThresholdSigCheck) {
        this.clientKey = clientKey;
        this.seed = seed;
        this.seedHex = new String(Hex.encode(seed));
        this.serverKey = serverKey;
        this.sigKey = sigKey;
        this.isDataIntegrityCheck = isDataIntegrityCheck != null && isDataIntegrityCheck;
        this.isThresholdSigCheck = isThresholdSigCheck != null && isThresholdSigCheck;

        if (this.sigKey != null) {
            sigPrivateKey = this.sigKey.getKeyPair().getPrivate();
        }

        if (sigPrivateKey == null && clientKey.getKeyPair() != null && clientKey.getKeyPair().getPrivate() != null) {
            //For API clients this key could as well be generated, since the public key is passed during login to be mapped
            this.sigPrivateKey = KeysProvider.deriveAccountSigKeyPair(clientKey.getKeyPair().getPrivate()).getPrivate();
        }
    }

    public String getPublicKey() {
        return clientKey.getEncodedPublicKey();
    }

    public PublicKey getClientPublicKey() {
        return clientKey != null && clientKey.getKeyPair() != null ? clientKey.getKeyPair().getPublic() : null;
    }

    public PrivateKey getClientPrivateKey() {
        return clientKey != null && clientKey.getKeyPair() != null ? clientKey.getKeyPair().getPrivate() : null;
    }

    public PublicKey getServerPublicKey() {
        return serverKey != null && serverKey.getKeyPair() != null ? serverKey.getKeyPair().getPublic() : null;
    }

    public PublicKey getServerSigKey() {
        return sigKey != null && sigKey.getKeyPair() != null ? sigKey.getKeyPair().getPublic() : null;
    }

    public String getServerEncodedPublicKey() {
        return serverKey != null ? serverKey.getEncodedPublicKey() : null;
    }

    public void setServerPublicKey(String serverPublicKey) {
        serverKey = KeysInfo.fromPublicKey(serverPublicKey);
    }

    public void setServerSigKey(String publicKey) {
        sigKey = KeysInfo.fromPublicKey(publicKey);
    }
}
