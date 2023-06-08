package com.weavechain.core.data;

import lombok.Getter;
import org.bitcoinj.base.Base58;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class MerkleTreeMap<K, V> extends AbstractMap<K, V> implements HashTree<K, V> {

    static final Logger logger = LoggerFactory.getLogger(MerkleTreeMap.class);

    public static final boolean KEEP_STORED_VALUES = false;

    private static final boolean KEEP_COUNTS = false;

    private static final boolean RED = false;

    private static final boolean BLACK = true;

    private transient Entry<K, V> root;

    private transient List<Entry<K, V>> entryList;

    private transient int size = 0;

    private final byte[] salt;

    private final List<List<byte[]>> levels = new ArrayList<>();

    private final Set<Integer> dirtyHashes = new TreeSet<>();

    @Getter
    private boolean enableRehashing = true;

    @Getter
    private String digest = null;

    public MerkleTreeMap(byte[] salt) {
        this.salt = salt;
    }

    public int size() {
        return size;
    }

    public void clear() {
        size = 0;
        root = null;
    }

    public Set<Map.Entry<K, V>> entrySet() {
        List<Entry<K, V>> entries = entryList();
        return new HashSet<>(entries); //temp suboptimal hack
    }

    public V get(Object key) {
        Entry<K, V> p = getEntry(key);
        return p == null ? null : p.getValue();
    }

    List<Entry<K, V>> entryList() {
        if (entryList == null) {
            entryList = new ArrayList<>();
            if (root != null) {
                inorderEntries(entryList, root);
            }
        }
        return entryList;
    }

    @Override
    public Collection<V> values() {
        List<V> result = new ArrayList<>();
        if (root != null) {
            inorderValues(result, root);
        }
        return result;
    }

    @Override
    public Set<K> keySet() {
        List<K> result = new ArrayList<>();
        if (root != null) {
            inorderKeys(result, root);
        }
        return new HashSet<>(result);
    }

    public List<byte[]> hashes() {
        List<byte[]> result = new ArrayList<>();
        if (root != null) {
            inorderHashes(result, root);
        }
        return result;
    }

    private static <K, V> void inorderEntries(List<Entry<K, V>> result, Entry<K, V> node) {
        if (node.getLeft() != null) {
            inorderEntries(result, node.getLeft());
        }
        result.add(node);
        if (node.getRight() != null) {
            inorderEntries(result, node.getRight());
        }
    }

    private static <K, V> void inorderValues(List<V> result, Entry<K, V> node) {
        if (node.getLeft() != null) {
            inorderValues(result, node.getLeft());
        }
        result.add(node.getValue());
        if (node.getRight() != null) {
            inorderValues(result, node.getRight());
        }
    }

    private static <K, V> void inorderKeys(List<K> result, Entry<K, V> node) {
        if (node.getLeft() != null) {
            inorderKeys(result, node.getLeft());
        }
        result.add(node.getKey());
        if (node.getRight() != null) {
            inorderKeys(result, node.getRight());
        }
    }

    private static <K, V> void inorderHashes(List<byte[]> result, Entry<K, V> node) {
        if (node.getLeft() != null) {
            inorderHashes(result, node.getLeft());
        }
        result.add(node.getHash());
        if (node.getRight() != null) {
            inorderHashes(result, node.getRight());
        }
    }

    @Override
    public V put(K key, V value) {
        V result = internalPut(key, value);
        updateHashes();
        return result;
    }


    @Override
    public V remove(Object key) {
        V result = internalRemove(key);
        updateHashes();
        return result;
    }

    private void updateHashes() {
        List<Entry<K, V>> items = entryList();
        List<byte[]> leaves = levels.size() > 0 ? levels.get(levels.size() - 1) : null;

        if (leaves == null) {
            buildTree(items);
        } else {
            updateHashes(items, leaves, 0, dirtyHashes);

            rehash();
        }
    }

    public void setEnableRehashing(boolean value) {
        if (value && !enableRehashing) {
            enableRehashing = true;
            rehash();
        }
    }

    private void rehash() {
        if (levels.get(0).size() > 1) {
            addLevels();
        }

        rehashParents(dirtyHashes);

        dirtyHashes.clear();
    }

    public void rebuildTree() {
        buildTree(entryList());
    }

    private void buildTree(List<Entry<K, V>> items) {
        levels.clear();

        List<byte[]> leaves;
        leaves = new ArrayList<>();
        for (Entry<K, V> entry : items) {
            leaves.add(entry.getHash());
            entry.resetDirty();
        }
        levels.add(leaves);

        addLevels();
    }

    private void addLevels() {
        while (levels.get(0).size() > 1) {
            List<byte[]> hashes = new ArrayList<>();
            int len = levels.get(0).size();
            List<byte[]> level = levels.get(0);
            for (int i = 0; i < len; i += 2) {
                if (i < len - 1) {
                    byte[] hash = hash2(level.get(i), level.get(i + 1), digest);
                    hashes.add(hash);
                } else {
                    hashes.add(level.get(i));
                }
            }
            levels.add(0, hashes);
        }
    }

    private void rehashParents(Set<Integer> dirtyHashes) {
        int idx = 1;
        while (idx < levels.size()) {
            Set<Integer> dirtyParents = new TreeSet<>();
            List<byte[]> level = levels.get(levels.size() - 1 - idx);
            List<byte[]> next = levels.get(levels.size() - idx);
            for (Integer i : dirtyHashes) {
                if (2 * i + 1 < next.size()) {
                    level.set(i, hash2(next.get(2 * i), next.get(2 * i + 1), digest));
                } else {
                    level.set(i, next.get(2 * i));
                }
                dirtyParents.add(i / 2);
            }
            dirtyHashes = dirtyParents;
            idx++;
        }
    }

    private void updateHashes(List<Entry<K, V>> items, List<byte[]> leaves, int startIdx, Set<Integer> dirtyHashes) {
        if (leaves.size() < items.size()) {
            int i = startIdx;
            Entry<K, V> entry = null;
            while (i < items.size()) {
                entry = items.get(i);
                byte[] entryHash = i < leaves.size() ? leaves.get(i) : null;
                if (entry.isHashDirty() && !Arrays.equals(entryHash, entry.getHash())) {
                    entry.resetDirty();
                    //TODO: imbalanced merkle tree to be able to do partial recompute. The current version is ok when doing appends (our default scenario)
                    for (int j = i; j < items.size(); j++) {
                        dirtyHashes.add(j / 2);
                    }
                    break;
                }
                i++;
            }
            if (entry != null) {
                if (i < leaves.size()) {
                    leaves.add(i, entry.getHash());
                } else {
                    leaves.add(entry.getHash());
                }

                for (int idx = 1; idx < levels.size(); idx++) {
                    i = i / 2;
                    List<byte[]> level = levels.get(levels.size() - 1 - idx);
                    List<byte[]> next = levels.get(levels.size() - idx);
                    if (level.size() < (next.size() + 1) / 2) {
                        if (2 * i + 1 < next.size()) {
                            level.add(i, hash2(next.get(2 * i), next.get(2 * i + 1), digest));
                        } else {
                            level.add(i, next.get(2 * i));
                        }
                    }
                }
                updateHashes(items, leaves, 0, dirtyHashes);
            }
        } else if (leaves.size() > items.size()) {
            int i = startIdx;
            while (i < items.size()) {
                Entry<K, V> entry = items.get(i);
                byte[] entryHash = i < leaves.size() ? leaves.get(i) : null;
                if (!Arrays.equals(entryHash, entry.getHash())) {
                    entry.resetDirty();
                    //TODO: imbalanced merkle tree to be able to do partial recompute. The current version is ok when doing appends (our default scenario)
                    for (int j = i; j < items.size(); j++) {
                        dirtyHashes.add(j / 2);
                    }
                    break;
                }
                i++;
            }
            if (i < leaves.size()) {
                leaves.remove(i);
            } else {
                dirtyHashes.add((leaves.size() - 1) / 2);
                leaves.remove(leaves.size() - 1);
            }
            updateHashes(items, leaves, 0, dirtyHashes);
        } else {
            for (int i = startIdx; i < items.size(); i++) {
                Entry<K, V> entry = items.get(i);
                byte[] entryHash = i < leaves.size() ? leaves.get(i) : null;
                if (!Arrays.equals(entryHash, entry.getHash())) {
                    entry.resetDirty();
                    dirtyHashes.add(i / 2);
                    leaves.set(i, entry.getHash());
                }
            }
        }
    }

    private V internalRemove(Object key) {
        Entry<K, V> p = getEntry(key);
        if (p == null) {
            return null;
        }

        V oldValue = p.getValue();
        deleteEntry(p);
        return oldValue;
    }

    @SuppressWarnings("unchecked")
    private V internalPut(K key, V value) {
        Entry<K, V> t = root;
        if (t == null) {
            compare(key, key);

            root = new Entry<>(key, value, null, this);
            entryList = null;
            size = 1;
            return null;
        }
        int cmp;
        Entry<K, V> parent;

        if (key == null) {
            throw new NullPointerException();
        }
        Comparable<? super K> k = (Comparable<? super K>) key;
        do {
            parent = t;
            cmp = k.compareTo(t.getKey());
            if (cmp < 0) {
                t = t.getLeft();
            } else if (cmp > 0) {
                t = t.getRight();
            } else {
                if (!Objects.equals(value, t.getValue())) {
                    return t.setValue(value);
                } else {
                    return value;
                }
            }
        } while (t != null);
        Entry<K, V> e = new Entry<>(key, value, parent, this);
        if (cmp < 0) {
            parent.setLeft(e);
        } else {
            parent.setRight(e);
        }
        fixAfterInsertion(e);
        size++;
        entryList = null;
        return null;
    }

    private void fixAfterInsertion(Entry<K, V> x) {
        x.setColor(RED);

        while (x != null && x != root && x.getParent().getColor() == RED) {
            if (parentOf(x) == leftOf(parentOf(parentOf(x)))) {
                Entry<K, V> y = rightOf(parentOf(parentOf(x)));
                if (colorOf(y) == RED) {
                    setColor(parentOf(x), BLACK);
                    setColor(y, BLACK);
                    setColor(parentOf(parentOf(x)), RED);
                    x = parentOf(parentOf(x));
                } else {
                    if (x == rightOf(parentOf(x))) {
                        x = parentOf(x);
                        rotateLeft(x);
                    }
                    setColor(parentOf(x), BLACK);
                    setColor(parentOf(parentOf(x)), RED);
                    rotateRight(parentOf(parentOf(x)));
                }
            } else {
                Entry<K, V> y = leftOf(parentOf(parentOf(x)));
                if (colorOf(y) == RED) {
                    setColor(parentOf(x), BLACK);
                    setColor(y, BLACK);
                    setColor(parentOf(parentOf(x)), RED);
                    x = parentOf(parentOf(x));
                } else {
                    if (x == leftOf(parentOf(x))) {
                        x = parentOf(x);
                        rotateRight(x);
                    }
                    setColor(parentOf(x), BLACK);
                    setColor(parentOf(parentOf(x)), RED);
                    rotateLeft(parentOf(parentOf(x)));
                }
            }
        }
        root.setColor(BLACK);
    }

    private static <K, V> Entry<K, V> successor(Entry<K, V> t) {
        if (t == null) {
            return null;
        } else if (t.getRight() != null) {
            Entry<K, V> p = t.getRight();
            while (p.getLeft() != null) {
                p = p.getLeft();
            }
            return p;
        } else {
            Entry<K, V> p = t.getParent();
            Entry<K, V> ch = t;
            while (p != null && ch == p.getRight()) {
                ch = p;
                p = p.getParent();
            }
            return p;
        }
    }

    private static <K, V> Entry<K, V> predecessor(Entry<K, V> t) {
        if (t == null) {
            return null;
        } else if (t.getLeft() != null) {
            Entry<K, V> p = t.getLeft();
            while (p.getRight() != null) {
                p = p.getRight();
            }
            return p;
        } else {
            Entry<K, V> p = t.getParent();
            Entry<K, V> ch = t;
            while (p != null && ch == p.getLeft()) {
                ch = p;
                p = p.getParent();
            }
            return p;
        }
    }

    private void deleteEntry(Entry<K, V> p) {
        size--;
        entryList = null;

        if (p.getLeft() != null && p.getRight() != null) {
            Entry<K, V> s = successor(p);
            p.setKey(s.getKey());
            p.setValue(s.getValue());
            p = s;
        }

        Entry<K, V> replacement = (p.getLeft() != null ? p.getLeft() : p.getRight());

        if (replacement != null) {
            replacement.setParent(p.getParent());
            if (p.parent == null) {
                root = replacement;
            } else if (p == p.getParent().getLeft()) {
                p.getParent().setLeft(replacement);
            } else {
                p.getParent().setRight(replacement);
            }

            p.setLeft(null);
            p.setRight(null);
            p.setParent(null);

            if (p.getColor() == BLACK) {
                fixAfterDeletion(replacement);
            }
        } else if (p.getParent() == null) {
            root = null;
        } else {
            if (p.getColor() == BLACK) {
                fixAfterDeletion(p);
            }

            if (p.getParent() != null) {
                if (p == p.getParent().getLeft()) {
                    p.getParent().setLeft(null);
                } else if (p == p.getParent().getRight()) {
                    p.getParent().setRight(null);
                }
                p.setParent(null);
            }
        }
    }

    private void rotateLeft(Entry<K, V> p) {
        if (p != null) {
            Entry<K, V> r = p.getRight();
            p.setRight(r.getLeft());
            if (r.getLeft() != null) {
                r.getLeft().setParent(p);
            }
            r.setParent(p.getParent());
            if (p.getParent() == null) {
                root = r;
            } else if (p.getParent().getLeft() == p) {
                p.getParent().setLeft(r);
            } else {
                p.getParent().setRight(r);
            }
            r.setLeft(p);
            p.setParent(r);
        }
    }

    private void rotateRight(Entry<K, V> p) {
        if (p != null) {
            Entry<K, V> l = p.getLeft();
            p.setLeft(l.getRight());
            if (l.getRight() != null) {
                l.getRight().setParent(p);
            }
            l.setParent(p.getParent());
            if (p.getParent() == null) {
                root = l;
            } else if (p.getParent().getRight() == p) {
                p.getParent().setRight(l);
            } else {
                p.getParent().setLeft(l);
            }
            l.setRight(p);
            p.setParent(l);
        }
    }

    private void fixAfterDeletion(Entry<K, V> x) {
        while (x != root && colorOf(x) == BLACK) {
            if (x == leftOf(parentOf(x))) {
                Entry<K, V> sib = rightOf(parentOf(x));

                if (colorOf(sib) == RED) {
                    setColor(sib, BLACK);
                    setColor(parentOf(x), RED);
                    rotateLeft(parentOf(x));
                    sib = rightOf(parentOf(x));
                }

                if (colorOf(leftOf(sib))  == BLACK && colorOf(rightOf(sib)) == BLACK) {
                    setColor(sib, RED);
                    x = parentOf(x);
                } else {
                    if (colorOf(rightOf(sib)) == BLACK) {
                        setColor(leftOf(sib), BLACK);
                        setColor(sib, RED);
                        rotateRight(sib);
                        sib = rightOf(parentOf(x));
                    }
                    setColor(sib, colorOf(parentOf(x)));
                    setColor(parentOf(x), BLACK);
                    setColor(rightOf(sib), BLACK);
                    rotateLeft(parentOf(x));
                    x = root;
                }
            } else { // symmetric
                Entry<K, V> sib = leftOf(parentOf(x));

                if (colorOf(sib) == RED) {
                    setColor(sib, BLACK);
                    setColor(parentOf(x), RED);
                    rotateRight(parentOf(x));
                    sib = leftOf(parentOf(x));
                }

                if (colorOf(rightOf(sib)) == BLACK && colorOf(leftOf(sib)) == BLACK) {
                    setColor(sib, RED);
                    x = parentOf(x);
                } else {
                    if (colorOf(leftOf(sib)) == BLACK) {
                        setColor(rightOf(sib), BLACK);
                        setColor(sib, RED);
                        rotateLeft(sib);
                        sib = leftOf(parentOf(x));
                    }
                    setColor(sib, colorOf(parentOf(x)));
                    setColor(parentOf(x), BLACK);
                    setColor(leftOf(sib), BLACK);
                    rotateRight(parentOf(x));
                    x = root;
                }
            }
        }

        setColor(x, BLACK);
    }

    @SuppressWarnings("unchecked")
    private int compare(Object k1, Object k2) {
        return ((Comparable<? super K>)k1).compareTo((K)k2);
    }

    @SuppressWarnings("unchecked")
    private Entry<K, V> getEntry(Object key) {
        if (key == null) {
            throw new NullPointerException();
        }
        Comparable<? super K> k = (Comparable<? super K>) key;
        Entry<K, V> p = root;
        while (p != null) {
            int cmp = k.compareTo(p.getKey());
            if (cmp < 0) {
                p = p.getLeft();
            } else if (cmp > 0) {
                p = p.getRight();
            } else {
                return p;
            }
        }
        return null;
    }

    private static <K, V> boolean colorOf(Entry<K, V> p) {
        return p == null ? BLACK : p.getColor();
    }

    private static <K, V> Entry<K, V> parentOf(Entry<K, V> p) {
        return p == null ? null : p.getParent();
    }

    private static <K, V> void setColor(Entry<K, V> p, boolean c) {
        if (p != null) {
            p.setColor(c);
        }
    }

    private static <K, V> Entry<K, V> leftOf(Entry<K, V> p) {
        return p == null ? null : p.getLeft();
    }

    private static <K, V> Entry<K, V> rightOf(Entry<K, V> p) {
        return p == null ? null : p.getRight();
    }

    @Override
    public String getRootHash() {
        return levels.size() > 0 && levels.get(0).size() > 0 ? Base58.encode(levels.get(0).get(0)) : (root != null ? Base58.encode(root.getHash()) : null);
    }

    @Override
    public boolean verifyHash(String recordHash) {
        if (levels.size() > 0) {
            byte[] hash = Base58.decode(recordHash);
            int idx = 0;
            List<byte[]> leaves = levels.get(levels.size() - 1);
            int len = leaves.size();
            while (idx < len) {
                if (Arrays.equals(hash, leaves.get(idx))) {
                    break;
                }
                idx++;
            }
            if (idx < len) {
                byte[] h1 = hash;
                for (int i = levels.size() - 1; i > 0; i--) {
                    if (!Arrays.equals(h1, levels.get(i).get(idx))) {
                        return false;
                    }

                    int p = idx + 1 - 2 * (idx % 2);
                    if (p < levels.get(i).size()) {
                        byte[] h2 = levels.get(i).get(p);
                        h1 = hash2(idx % 2 == 0 ? h1 : h2, idx % 2 == 0 ? h2 : h1, digest);
                    }

                    idx = (idx - (idx % 2)) / 2;
                }
                return Arrays.equals(h1, levels.get(0).get(0));
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
    public List<String> getMerkleProof(String recordHash) {
        List<String> result = new ArrayList<>();
        if (levels.size() > 0) {
            byte[] hash = Base58.decode(recordHash);
            int idx = 0;
            List<byte[]> leaves = levels.get(levels.size() - 1);
            int len = leaves.size();
            while (idx < len) {
                if (Arrays.equals(hash, leaves.get(idx))) {
                    break;
                }
                idx++;
            }
            if (idx < len) {
                byte[] h1 = hash;
                for (int i = levels.size() - 1; i > 0; i--) {
                    if (!Arrays.equals(h1, levels.get(i).get(idx))) {
                        return null;
                    }

                    int p = idx + 1 - 2 * (idx % 2);
                    if (p < levels.get(i).size()) {
                        byte[] h2 = levels.get(i).get(p);
                        byte[] left = idx % 2 == 0 ? h1 : h2;
                        byte[] right = idx % 2 == 0 ? h2 : h1;
                        result.add(Base58.encode(left) + "," + Base58.encode(right));
                        h1 = hash2(left, right, digest);
                    }

                    idx = (idx - (idx % 2)) / 2;
                }
                return Arrays.equals(h1, levels.get(0).get(0)) ? result : null;
            } else {
                logger.error("Object not found");
                return null;
            }
        } else {
            logger.error("Empty tree");
            return null;
        }
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();

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

    public static boolean verifyProof(String recordHash, String proof, String rootHash, String digest) {
        return MerkleTree.verifyProof(recordHash, proof, rootHash, digest);
    }

    public byte[] hash2(byte[] data1, byte[] data2, String digest) {
        byte[] data = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, data, 0, data1.length);
        System.arraycopy(data2, 0, data, data1.length, data2.length);
        return MerkleTree.hash(data, digest);
    }

    @Getter
    static final class Entry<K, V> implements Map.Entry<K, V> {

        private K key;

        private V value;

        private byte[] hash;

        private boolean hashDirty = true;

        private boolean posDirty;

        private Entry<K, V> left;

        private Entry<K, V> right;

        private Entry<K, V> parent;

        private boolean color = BLACK;

        private int nodesCount;

        private final MerkleTreeMap<K, V> owner;

        Entry(K key, V value, Entry<K, V> parent, MerkleTreeMap<K, V> owner) {
            this.key = key;
            this.value = value;
            this.parent = parent;
            this.owner = owner;
            rehash();
            updateCounter();
        }

        public K setKey(K key) {
            K oldKey = this.key;
            this.key = key;
            return oldKey;
        }

        public V setValue(V value) {
            V oldValue = this.value;
            this.value = value;
            rehash();
            return oldValue;
        }

        public boolean getColor() {
            return this.color;
        }

        public void setColor(boolean color) {
            this.color = color;
        }

        public void resetDirty() {
            this.hashDirty = false;
            this.posDirty = false;
        }

        public void setLeft(Entry<K, V> left) {
            this.left = left;
            this.posDirty = true;
            updateCounter();
        }

        public void setRight(Entry<K, V> right) {
            this.right = right;
            this.posDirty = true;
            updateCounter();
        }

        public void setParent(Entry<K, V> parent) {
            this.parent = parent;
            this.posDirty = true;
            if (parent != null) {
                parent.updateCounter();
            }
        }

        private void rehash() {
            this.hash = MerkleTree.buildRecordHash(this.owner.salt, this.value, null, owner.getDigest());
            if (!KEEP_STORED_VALUES) {
                this.value = null;
            }
            this.hashDirty = true;
        }

        private void updateCounter() {
            if (KEEP_COUNTS) {
                this.nodesCount = (this.left != null ? this.left.getNodesCount() : 0) + (this.right != null ? this.right.getNodesCount() : 0) + 1;
                if (parent != null) {
                    this.parent.updateCounter();
                }
            }
        }

        @Override
        public int hashCode() {
            return key != null ? key.hashCode() : 0;
        }

        @Override
        public boolean equals(Object other) {
            if (other instanceof Entry) {
                return Objects.equals(key, ((Entry<?, ?>) other).getKey())
                        && Objects.equals(value, ((Entry<?, ?>) other).getValue());
            } else {
                return false;
            }
        }

        @Override
        public String toString() {
            return key + "=" + value;
        }
    }
}
