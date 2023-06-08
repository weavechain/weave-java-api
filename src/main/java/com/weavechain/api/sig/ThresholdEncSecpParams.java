package com.weavechain.api.sig;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

@Getter
@AllArgsConstructor
public class ThresholdEncSecpParams {

    //dummy BigInteger implementation, switch to byte[]

    private final BigInteger privateKey;

    private final BigInteger publicKey;

    private final List<BigInteger> privateShares;

    private final List<ECPoint> publicShares;
}