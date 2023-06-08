package com.weavechain.core.encrypt;

public abstract class FieldEncrypt {

    public static FieldEncrypt getEncryptor(String algorithm) {
        if (EncryptionConfig.CHACHAPOLY.equals(algorithm)) {
            return new ChaChaPolyFieldEncrypt();
        } else {
            return new AESFieldEncrypt();
        }
    }

    public abstract void init(String key, String salt);

    public abstract Object encrypt(Object value);

    public abstract Object decrypt(Object value);
}