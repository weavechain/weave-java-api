package com.weavechain.core.encrypt;

import java.security.SecureRandom;

public class Seed {

    public static final String PUBLIC_CHAIN_SEED = "f2fbff18252909d2a5ade53820dd7941";

    public static final String TEST_CHAIN_SEED = "9efd86b97699a7794b99766e03794b5c";

    public static byte[] generate() {
        return generate(16);
    }

    public static byte[] generate(int bytes) {
        return new SecureRandom().generateSeed(bytes);
    }
}
