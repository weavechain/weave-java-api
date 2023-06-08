package com.weavechain.core.data;

import cafe.cryptography.curve25519.Scalar;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
public class ThresholdSigEd25519Param {

    private final byte[] publicKey;

    private final Scalar privateShare;

    @Setter
    private Scalar sig;

    private int index;

    public ThresholdSigEd25519Param(byte[] publicKey, Scalar privateShare, int index) {
        this.publicKey = publicKey;
        this.privateShare = privateShare;
        this.index = index;
    }
}