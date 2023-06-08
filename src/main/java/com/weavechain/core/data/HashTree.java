package com.weavechain.core.data;

import java.util.List;

public interface HashTree<K, V> {

    String getRootHash();

    boolean verifyHash(String hash);

    List<String> getMerkleProof(String hash);

    V put(K key, V value);
}
