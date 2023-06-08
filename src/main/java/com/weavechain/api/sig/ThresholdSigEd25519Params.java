package com.weavechain.api.sig;

import cafe.cryptography.curve25519.Scalar;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@AllArgsConstructor
public class ThresholdSigEd25519Params {

    private final Scalar privateKey;

    private final byte[] publicKey;

    private final List<Scalar> privateShares;

    @Setter
    private List<Scalar> sig;
}