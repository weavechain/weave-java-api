package com.weavechain.core.data;

import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.Hash;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bitcoinj.base.Base58;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@AllArgsConstructor
public class MerkleTree implements HashTree<Object, Object> {

    //TODO: maybe add order randomization and leaf splitting (most likely should be app specific)

    static final Logger logger = LoggerFactory.getLogger(MerkleTree.class);

    private static final String DEFAULT_HASH = Hash.SHA256;

    private static final byte[] NULL_HASH = new byte[0];

    private final List<List<?>> hashes = new ArrayList<>();

    private final List<List<BigDecimal>> sums = new ArrayList<>();

    private boolean hasRawData;

    @Getter
    private String rootHash;

    private String digest = null;

    private static boolean hashTwice = false;

    private static final Map<String, ThreadLocal<MessageDigest>> messageDigest = Utils.newConcurrentHashMap();

    public static String hash(String data, String digest) {
        return Base58.encode(hash(data.getBytes(StandardCharsets.UTF_8), digest));
    }

    public static String digestMapping(String digest) {
        return digest != null ? digest : DEFAULT_HASH;
    }

    @Override
    public Object put(Object key, Object value) {
        throw new IllegalArgumentException("Not implemented");
    }

    public static byte[] hash(byte[] data, String digest) {
        MessageDigest md = messageDigest.computeIfAbsent(digestMapping(digest), (d) -> ThreadLocal.withInitial(() -> {
            try {
                return MessageDigest.getInstance(d);
            } catch (NoSuchAlgorithmException e) {
                logger.error("Failed message digest initialization", e);
                return null;
            }
        })).get();

        if (hashTwice) {
            data = hash(data, md);
        }

        return hash(data, md);
    }

    private static byte[] hash(byte[] data, MessageDigest md) {
        if (md != null) {
            md.reset();
            md.update(data);
            return md.digest();
        } else {
            return null;
        }
    }

    public static byte[] hash2(byte[] data1, byte[] data2, String digest) {
        byte[] data = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, data, 0, data1.length);
        System.arraycopy(data2, 0, data, data1.length, data2.length);
        return hash(data, digest);
    }

    public static byte[] hash2sum(byte[] data1, byte[] data2, BigDecimal v1, BigDecimal v2, String digest) {
        byte[] h1 = mergeBytes(data1, v1);
        byte[] h2 = mergeBytes(data2, v2);

        byte[] data = new byte[h1.length + h2.length];
        System.arraycopy(h1, 0, data, 0, h1.length);
        System.arraycopy(h2, 0, data, h1.length, h2.length);
        return hash(data, digest);
    }

    private static byte[] mergeBytes(byte[] data, BigDecimal v) {
        byte[] vbytes = v.unscaledValue().toByteArray();
        byte[] result = new byte[data.length + vbytes.length];
        System.arraycopy(data, 0, result, 0, data.length);
        System.arraycopy(vbytes, 0, result, data.length, vbytes.length);
        return result;
    }

    public static String hash2(String hash1, String hash2, String digest) {
        byte[] left = Base58.decode(hash1);
        byte[] right = Base58.decode(hash2);
        return Base58.encode(hash2(left, right, digest));
    }

    public static String hash2(String hashes, String digest) {
        String[] h = hashes.split(",");
        if (h.length == 2) {
            byte[] left = Base58.decode(h[0]);
            byte[] right = Base58.decode(h[1]);
            return Base58.encode(hash2(left, right, digest));
        } else {
            return null;
        }
    }

    public static MerkleTree createTree(String hashes, String digest) {
        MerkleTree result = new MerkleTree(false, null, digest);
        String[] data = hashes.split(";");

        for (String item : data) {
            String[] row = item.split(",");
            result.hashes.add(List.of(row));

            if (row.length == 1) {
                result.rootHash = row[0];
            }
        }

        return result;
    }

    public static MerkleTree createTree(byte[] dataHashes, String digest) throws IOException {
        MerkleTree result = new MerkleTree(false, null, null);
        ByteArrayInputStream input = new ByteArrayInputStream(dataHashes);

        int len = Hash.getHashLength(digest);
        List<Object> hashes = new ArrayList<>();
        while (input.available() > 0) {
            byte[] hash = input.readNBytes(len);
            String encoded = Base58.encode(hash);
            hashes.add(encoded);
        }
        result.hashes.add(hashes);

        buildTree(result, digest);

        return result;
    }

    public static MerkleTree createTree(List<?> data, String digest) {
        return createTree(data, null, digest);
    }

    public static MerkleTree createTree(List<?> data, byte[] salt, String digest) {
        return createTree(data, salt, null, null, digest);
    }

    public static MerkleTree createTree(List<?> data, byte[] salt, Integer sumColumnIndex, Long nonce, String digest) {
        MerkleTree result = new MerkleTree(true, null, digest);

        result.hashes.add(data);

        if (data.size() > 0) {
            List<Object> hashes = new ArrayList<>();
            List<BigDecimal> sums = new ArrayList<>();
            for (Object o : data) {
                byte[] hash = buildRecordHash(salt, o, nonce, digest);

                String encoded = Base58.encode(hash);
                hashes.add(encoded);
            }
            result.hashes.add(0, hashes);
        }

        if (sumColumnIndex != null) {
            List<BigDecimal> leafValues = new ArrayList<>();
            for (Object o : data) {
                if (o instanceof List) {
                    BigDecimal value = ConvertUtils.convertToBigDecimal(((List)o).get(sumColumnIndex));
                    leafValues.add(value);
                }
            }
            result.sums.add(leafValues);
        }

        buildTree(result, digest);

        return result;
    }

    public static byte[] buildRecordHash(byte[] salt, Object o, Long nonce, String digest) {
        byte[] hash;
        if (o instanceof List && salt != null) {
            String encoded = Utils.getListJsonAdapter().toJson((List) o);
            hash = Hash.signString(salt, encoded, digest);
        } else {
            String obj = o != null ? (o instanceof List ? Utils.getGson().toJson(o) : ConvertUtils.convertToString(o)) : null;

            if (nonce != null) {
                obj += " " + nonce;
            }

            //TODO: review, maybe use batching of records or use the same salted hash as in signers
            // Alternatively just build the tree out of batches hashes?
            if (salt != null) {
                hash = obj != null ? Hash.signString(salt, obj, digest) : NULL_HASH;
            } else {
                hash = obj != null ? hash(obj.getBytes(StandardCharsets.UTF_8), digest) : NULL_HASH;
            }
        }
        return hash;
    }

    private static void buildTree(MerkleTree result, String digest) {
        if (result.hashes.get(0).size() == 1) {
            List<?> level = result.hashes.get(0);
            result.rootHash = level.get(0).toString();
        }

        while (result.hashes.get(0).size() > 1) {
            List<Object> hashes = new ArrayList<>();
            List<BigDecimal> sums = new ArrayList<>();

            int len = result.hashes.get(0).size();
            List<?> level = result.hashes.get(0);
            List<BigDecimal> levelSums = result.sums.size() > 0 ? result.sums.get(0) : null;

            for (int i = 0; i < len; i += 2) {
                if (i < len - 1) {
                    if (levelSums != null) {
                        byte[] hash = hash2sum(Base58.decode((String)level.get(i)), Base58.decode((String)level.get(i + 1)), levelSums.get(i), levelSums.get(i + 1), digest);
                        hashes.add(Base58.encode(hash));

                        sums.add(levelSums.get(i).add(levelSums.get(i + 1)));
                    } else {
                        byte[] hash = hash2(Base58.decode((String)level.get(i)), Base58.decode((String)level.get(i + 1)), digest);
                        hashes.add(Base58.encode(hash));
                    }
                } else {
                    hashes.add(level.get(i));
                    if (levelSums != null) {
                        sums.add(levelSums.get(i));
                    }
                }
            }
            result.hashes.add(0, hashes);
            if (levelSums != null) {
                result.sums.add(0, sums);
            }

            if (hashes.size() == 1) {
                result.rootHash = hashes.get(0).toString();
            }
        }
    }

    public boolean verifyData(Object data) {
        return verifyData(null, data, null, null);
    }

    public boolean verifyData(byte[] salt, Object data, Integer sumColumnIndex, Long nonce) {
        if (hashes.size() > 1) {
            byte[] hash = data != null ? buildRecordHash(salt, data, nonce, digest) : NULL_HASH;
            BigDecimal value = sumColumnIndex != null && data instanceof List ? ConvertUtils.convertToBigDecimal(((List)data).get(sumColumnIndex))  : null;

            return verifyHash(Base58.encode(hash), value);
        } else {
            logger.warn("Empty tree");
            return false;
        }
    }

    @Override
    public boolean verifyHash(String hash) {
        return verifyHash(hash, null);
    }

    public boolean verifyHash(String hash, BigDecimal value) {
        if (hashes.size() > (hasRawData ? 1 : 0)) {
            int idx = hashes.get(hashes.size() - 1 - (hasRawData ? 1 : 0)).indexOf(hash);
            if (idx >= 0) {
                String h1 = hash;
                BigDecimal v1 = value;
                for (int i = hashes.size() - 1 - (hasRawData ? 1 : 0); i > 0; i--) {
                    List<?> level = hashes.get(i);
                    List<BigDecimal> levelSums = sums.size() > i ? sums.get(i) : null;

                    if (!h1.equals(level.get(idx))) {
                        return false;
                    }

                    int p = idx + 1 - 2 * (idx % 2);
                    if (p < level.size()) {
                        String h2 = (String) level.get(p);

                        if (levelSums != null) {
                            BigDecimal v2 = p < levelSums.size() ? levelSums.get(p) : null;
                            if (v2 == null) {
                                logger.error("Invalid value");
                                return false;
                            }

                            byte[] h = hash2sum(Base58.decode(idx % 2 == 0 ? h1 : h2), Base58.decode(idx % 2 == 0 ? h2 : h1), idx % 2 == 0 ? v1 : v2, idx % 2 == 0 ? v2 : v1, digest);
                            h1 = Base58.encode(h);
                            v1 = v1.add(v2);
                        } else {
                            byte[] h = hash2(Base58.decode(idx % 2 == 0 ? h1 : h2), Base58.decode(idx % 2 == 0 ? h2 : h1), digest);
                            h1 = Base58.encode(h);
                        }
                    }

                    idx = (idx - (idx % 2)) / 2;
                }
                return h1.equals(hashes.get(0).get(0));
            } else {
                logger.error("Object not found");
                return false;
            }
        } else {
            logger.error("Empty tree");
            return false;
        }
    }

    @Override
    public List<String> getMerkleProof(String hash) {
        return getMerkleProof(hash, null);
    }

    public List<String> getMerkleProof(String hash, BigDecimal value) {
        List<String> result = new ArrayList<>();
        if (hashes.size() > (hasRawData ? 1 : 0)) {
            int idx = hashes.get(hashes.size() - 1 - (hasRawData ? 1 : 0)).indexOf(hash);
            if (idx >= 0) {
                String h1 = hash;
                BigDecimal v1 = value;
                int startIdx = hashes.size() - 1 - (hasRawData ? 1 : 0);
                for (int i = startIdx; i > 0; i--) {
                    List<?> level = hashes.get(i);
                    List<BigDecimal> levelSums = sums.size() > i ? sums.get(i) : null;

                    if (!h1.equals(level.get(idx))) {
                        return null;
                    }

                    int p = idx + 1 - 2 * (idx % 2);
                    if (p < level.size()) {
                        String h2 = (String) level.get(p);
                        String left = idx % 2 == 0 ? h1 : h2;
                        String right = idx % 2 == 0 ? h2 : h1;
                        String row = left + "," + right;

                        if (levelSums != null) {
                            BigDecimal v2 = p < levelSums.size() ? levelSums.get(p) : null;
                            if (v2 == null) {
                                logger.error("Invalid value");
                                return null;
                            }

                            row += "," + (idx % 2 == 0 ? v1 : v2).toString() + "," + (idx % 2 == 0 ? v2 : v1).toString();

                            byte[] h = hash2sum(Base58.decode(idx % 2 == 0 ? h1 : h2), Base58.decode(idx % 2 == 0 ? h2 : h1), idx % 2 == 0 ? v1 : v2, idx % 2 == 0 ? v2 : v1, digest);
                            h1 = Base58.encode(h);
                            v1 = v1.add(v2);
                        } else {
                            byte[] h = hash2(Base58.decode(left), Base58.decode(right), digest);
                            h1 = Base58.encode(h);
                        }

                        result.add(row);
                    }

                    idx = (idx - (idx % 2)) / 2;
                }

                if (startIdx == 0) {
                    result.add(rootHash);
                }

                return h1.equals(hashes.get(0).get(0)) ? result : null;
            } else {
                logger.error("Object not found");
                return null;
            }
        } else {
            logger.error("Empty tree");
            return null;
        }
    }

    public static boolean verifyProof(String recordHash, String proof, String rootHash, String digest) {
        return verifyProof(recordHash, null, proof, rootHash, null, digest);
    }

    public static boolean verifyProof(String recordHash, BigDecimal value, String proof, String rootHash, BigDecimal rootSum, String digest) {
        if (proof != null) {
            try {
                String toCheck = recordHash;
                BigDecimal sumToCheck = value;
                for (String it : proof.split(";")) {
                    String[] row = it.split(",");
                    if (row.length >= 2 && (Objects.equals(row[0], toCheck) || Objects.equals(row[1], toCheck))) {
                        byte[] left = Base58.decode(row[0]);
                        byte[] right = Base58.decode(row[1]);

                        if (row.length >= 4) {
                            BigDecimal v1 = new BigDecimal(row[2]);
                            BigDecimal v2 = new BigDecimal(row[3]);

                            if (Objects.equals(row[0], toCheck)) {
                                if (!sumToCheck.equals(v1)) {
                                    return false;
                                }
                            } else {
                                if (!sumToCheck.equals(v2)) {
                                    return false;
                                }
                            }

                            byte[] hash = hash2sum(left, right, v1, v2, digest);
                            toCheck = Base58.encode(hash);

                            sumToCheck = v1.add(v2);
                        } else {
                            byte[] hash = hash2(left, right, digest);
                            toCheck = Base58.encode(hash);
                        }
                    } else {
                        return row.length == 1 && Objects.equals(row[0], toCheck);
                    }
                }

                return Objects.equals(rootHash, toCheck)
                        && (sumToCheck == null || sumToCheck.equals(rootSum));
            } catch (Exception e) {
                logger.error("Failed checking proof", e);
                return false;
            }
        } else {
            return false;
        }
    }

    public List<String> leavesHashes() {
        List<String> result = new ArrayList<>();
        List<?> hashes = this.hashes.get(this.hashes.size() - 1 - (hasRawData ? 1 : 0));
        for (Object h : hashes) {
            result.add(ConvertUtils.convertToString(h));
        }
        return result;
    }

    public BigDecimal getRootSum() {
        return sums != null && sums.size() > 0 && sums.get(0).size() == 1 ? sums.get(0).get(0) : null;
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < hashes.size() - (hasRawData ? 1 : 0); i++) {
            if (i > 0) {
                sb.append(";");
            }
            List<?> level = hashes.get(i);
            for (int j = 0; j < level.size(); j++) {
                if (j > 0) {
                    sb.append(",");
                }
                sb.append(level.get(j).toString());
            }
        }

        return sb.toString();
    }
}
