package com.weavechain.core.encrypt;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class EncryptionConfig {

    public static final String NONE = "none";

    public static final String AES = "AES";

    public static final String CHACHAPOLY = "ChaCha20-Poly1305";

    public static final EncryptionConfig NO_ENCRYPTION = new EncryptionConfig(NONE, null, null);

    public static final EncryptionConfig DEFAULT = NO_ENCRYPTION;

    private String type;

    private String secretKey;

    private String salt; // This is a quick workaround to enable encryption for tables that do not have an IV column, for safety we need a different IV for each piece of data

    public EncryptionConfig type(String value) {
        this.type = value;
        return this;
    }

    public EncryptionConfig copy() {
        return new EncryptionConfig(
                type,
                secretKey,
                salt
        );
    }
}