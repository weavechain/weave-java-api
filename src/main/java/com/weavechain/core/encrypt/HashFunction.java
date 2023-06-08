package com.weavechain.core.encrypt;

public interface HashFunction {

    byte[] digest(String data);

    String hexDigest(String data);

    String b58Digest(String data);
}