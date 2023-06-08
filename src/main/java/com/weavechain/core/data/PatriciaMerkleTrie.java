package com.weavechain.core.data;

import lombok.Getter;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;
import org.bitcoinj.base.Base58;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.besu.ethereum.trie.*;
import org.hyperledger.besu.plugin.services.exception.StorageException;
import org.hyperledger.besu.plugin.services.storage.KeyValueStorage;
import org.hyperledger.besu.plugin.services.storage.KeyValueStorageTransaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Stream;

public class PatriciaMerkleTrie implements HashTree<Object, Object> {

    static final Logger logger = LoggerFactory.getLogger(PatriciaMerkleTrie.class);

    private static final int STORAGE_THREADS = 1;

    private final static BouncyCastleProvider provider = new BouncyCastleProvider();

    static {
        Security.addProvider(provider);
    }

    private final byte[] salt;

    private final Set<Object> keys = new TreeSet<>();

    private final StoredMerklePatriciaTrie<Bytes, Bytes> trie;

    private final MerkleStorage merkleStorage;

    @Getter
    private String digest = null;

    public PatriciaMerkleTrie(byte[] salt) {
        this.salt = salt;

        merkleStorage = new KeyValueMerkleStorage(new KeyValueStorage() {
            @Override
            public void clear() throws StorageException {

            }

            @Override
            public boolean containsKey(byte[] key) throws StorageException {
                return false;
            }

            @Override
            public Optional<byte[]> get(byte[] key) throws StorageException {
                return Optional.empty();
            }

            @Override
            public Stream<Pair<byte[], byte[]>> stream() throws StorageException {
                return null;
            }

            @Override
            public Stream<byte[]> streamKeys() throws StorageException {
                return null;
            }

            @Override
            public boolean tryDelete(byte[] key) throws StorageException {
                return false;
            }

            @Override
            public Set<byte[]> getAllKeysThat(Predicate<byte[]> returnCondition) {
                return null;
            }

            @Override
            public Set<byte[]> getAllValuesFromKeysThat(Predicate<byte[]> returnCondition) {
                return null;
            }

            @Override
            public KeyValueStorageTransaction startTransaction() throws StorageException {
                return null;
            }

            @Override
            public void close() throws IOException {

            }
        });
        trie = new org.hyperledger.besu.ethereum.trie.StoredMerklePatriciaTrie<>(merkleStorage::get, value -> value, value -> value);
    }

    public String getRootHash() {
        return Base58.encode(trie.getRootHash().toArray());
    }

    public Bytes get(Object key) {
        byte[] bytes = getKeyBytes(key);
        Optional<Bytes> result = trie.get(Bytes.of(bytes));
        return result.isPresent() ? result.get() : null;
    }

    @Override
    public Object put(Object key, Object value) {
        byte[] hash = MerkleTree.buildRecordHash(this.salt, value, null, digest);
        byte[] bytes = getKeyBytes(key);
        keys.add(key);

        trie.put(Bytes.of(bytes), Bytes.of(hash));
        trie.commit(merkleStorage::put);
        return null;
    }

    public void remove(Object key) {
        byte[] bytes = getKeyBytes(key);
        keys.remove(key);
        trie.remove(Bytes.of(bytes));
    }

    public int size() {
        return keys.size();
    }

    public List<byte[]> storedHashes() {
        try {
            List<byte[]> result = new ArrayList<>();
            trie.visitLeafs((keyHash, node) -> {
                result.add(node.getValue().get().toArray());
                return TrieIterator.State.CONTINUE;
            });

            return result;
        } catch (Exception e) {
            logger.error("Failed reading hashes", e);
            return null;
        }
    }

    private byte[] getKeyBytes(Object key) {
        byte[] bytes;
        try {
            long val = ConvertUtils.convertToLong(key);
            ByteBuffer longBuffer = ByteBuffer.allocate(32);
            longBuffer.putLong(val);
            bytes = longBuffer.array();
        } catch (Exception e) {
            String val = ConvertUtils.convertToString(key);
            bytes = val.getBytes(StandardCharsets.UTF_8);
        }
        return bytes;
    }

    private List<List<byte[]>> getLeafValues() {
        List<List<byte[]>> levels = new ArrayList<>();
        levels.add(storedHashes());
        return levels;
    }

    @Override
    public boolean verifyHash(String recordHash) {
        byte[] hash = Base58.decode(recordHash);

        AtomicReference<Bytes> leafKeyHash = new AtomicReference<>();
        trie.visitLeafs((keyHash, node) -> {
            if (Arrays.equals(hash, node.getValue().get().toArray())) {
                leafKeyHash.set(keyHash);
                return TrieIterator.State.STOP;
            } else {
                return TrieIterator.State.CONTINUE;
            }
        });

        if (leafKeyHash.get() != null) {
            Proof<Bytes> proof = trie.getValueWithProof(leafKeyHash.get());
            //proof.getProofRelatedNodes();
            return proof.getValue().isPresent();
        } else {
            logger.error("Object not found");
            return false;
        }
    }

    private static byte[] hash2(int idx, byte[] h1, byte[] h2) {
        byte[] b = new byte[h1.length + h2.length];
        byte src[] = idx % 2 == 0 ? h1 : h2;
        int srclen = src.length;
        System.arraycopy(src, 0, b, 0, srclen);
        src = idx % 2 == 0 ? h2 : h1;
        System.arraycopy(src, srclen, b, 0, src.length);
        h1 = Hash.keccak256(b);
        return h1;
    }

    @Override
    public List<String> getMerkleProof(String recordHash) {
        byte[] hash = Base58.decode(recordHash);

        AtomicReference<Bytes> leafKeyHash = new AtomicReference<>();
        trie.visitLeafs((keyHash, node) -> {
            if (Arrays.equals(hash, node.getValue().get().toArray())) {
                leafKeyHash.set(keyHash);
                return TrieIterator.State.STOP;
            } else {
                return TrieIterator.State.CONTINUE;
            }
        });

        if (leafKeyHash.get() != null) {
            Proof<Bytes> proof = trie.getValueWithProof(leafKeyHash.get());
            List<String> result = new ArrayList<>();
            for (Bytes it : proof.getProofRelatedNodes()) {
                result.add(Base58.encode(it.toArray()));
            }
            return result;
        } else {
            logger.error("Object not found");
            return null;
        }
    }

    public static boolean verifyProof(String recordHash, String proof, String rootHash) {
        if (proof != null) {
            try {
                List<Bytes> proofRelatedNodes = new ArrayList<>();
                for (String it : proof.split(";")) {
                    proofRelatedNodes.add(Bytes.wrap(Base58.decode(it)));
                }
                List<Node<Bytes>> nodes1 = TrieNodeDecoder.decodeNodes(null, proofRelatedNodes.get(0));
                if (Objects.equals(rootHash, Base58.encode(nodes1.get(0).getHash().toArray()))) {
                    List<Node<Bytes>> nodes2 = TrieNodeDecoder.decodeNodes(null, proofRelatedNodes.get(proofRelatedNodes.size() - 1));

                    byte[] hash = Base58.decode(recordHash);
                    for (Node<Bytes> n : nodes2) {
                        if (n.getValue().isPresent()) {
                            if (Arrays.equals(hash, n.getValue().get().toArray())) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            } catch (Exception e) {
                logger.error("Failed checking proof", e);
                return false;
            }
        } else {
            return false;
        }
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();

        List<List<byte[]>> levels = getLeafValues();
        List<byte[]> nodeHashes = new ArrayList<>();

        trie.visitAll(new Consumer<Node<Bytes>>() {
            @Override
            public void accept(Node<Bytes> node) {
                nodeHashes.add(node.getHash().toArray());
            }
        });

        levels.add(0, nodeHashes.subList(1, nodeHashes.size()));
        levels.add(0, nodeHashes.subList(0, 1));

        for (int i = 0; i < levels.size(); i++) {
            if (i > 0) {
                sb.append(";");
            }
            List<byte[]> level = levels.get(i);
            for (int j = 0; j < level.size(); j++) {
                if (j > 0) {
                    sb.append(",");
                }
                sb.append(Base58.encode(level.get(j)));
            }
        }

        return sb.toString();
    }
}
