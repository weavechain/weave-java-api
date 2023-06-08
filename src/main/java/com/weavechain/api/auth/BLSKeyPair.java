package com.weavechain.api.auth;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public final class BLSKeyPair {

    private final byte[] publicKey;

    private final byte[] secretKey;
}