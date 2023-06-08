package com.weavechain.core.encrypt;

import org.bitcoinj.base.Base58;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

import java.util.function.Supplier;

public class HashSHA3 implements HashFunction {

    private final ThreadLocal<SHA3.DigestSHA3> digestSHA3;

    public HashSHA3() {
        this(SHA3.Digest512::new);
    }

    public HashSHA3(Supplier<SHA3.DigestSHA3> supplier) {
        digestSHA3 = ThreadLocal.withInitial(supplier);
    }

    @Override
    public byte[] digest(String data) {
        return digestSHA3.get().digest(data.getBytes());
    }

    @Override
    public String hexDigest(String data) {
        return Hex.toHexString(digest(data));
    }

    @Override
    public String b58Digest(String data) {
        return Base58.encode(digest(data));
    }
}
