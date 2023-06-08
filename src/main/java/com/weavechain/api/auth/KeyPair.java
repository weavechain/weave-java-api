package com.weavechain.api.auth;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class KeyPair {

    private final String publicKey;

    private final String privateKey;
}
