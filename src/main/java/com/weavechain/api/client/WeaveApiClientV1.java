package com.weavechain.api.client;

import cafe.cryptography.curve25519.Scalar;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.weavechain.api.ApiContext;
import com.weavechain.api.admin.TableInfo;
import com.weavechain.api.auth.BLSKeyPair;
import com.weavechain.api.auth.KeyPair;
import com.weavechain.api.auth.Keys;
import com.weavechain.api.client.http.HttpApiClient;
import com.weavechain.zk.bulletproofs.BulletProofs;
import com.weavechain.zk.bulletproofs.PedersenCommitment;
import com.weavechain.zk.bulletproofs.Proof;
import com.weavechain.core.encrypt.EncryptionConfig;
import com.weavechain.api.enc.EncryptionHelper;
import com.weavechain.api.pre.ClientEncryptedData;
import com.weavechain.api.pre.PREHelper;
import com.weavechain.api.pre.ProxyEncryptedData;
import com.weavechain.api.session.Session;
import com.weavechain.api.sig.SchnorrNIZK;
import com.weavechain.api.sig.SigUtils;
import com.weavechain.zk.bulletproofs.gadgets.Gadgets;
import com.weavechain.zk.bulletproofs.gadgets.MiMC;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.MerkleTree;
import com.weavechain.core.data.Records;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.Hash;
import com.weavechain.core.encrypt.KeyExchange;
import com.weavechain.core.encrypt.KeysInfo;
import com.weavechain.core.encrypt.KeysProvider;
import com.weavechain.core.error.*;
import com.weavechain.core.operations.WriteOptions;
import com.weavechain.core.operations.ZKOptions;
import com.weavechain.core.requests.RequestType;
import com.weavechain.core.utils.CompletableFuture;
import lombok.Getter;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HTTP;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bitcoinj.base.Base58;

import javax.crypto.SecretKey;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public abstract class WeaveApiClientV1 implements ApiClientV1 {

    static final Logger logger = LoggerFactory.getLogger(WeaveApiClientV1.class);

    private static final String VERSION = "v1";

    private static final int TABLE_DEF_TIMEOUT_MS = 1_000; //ideally all timeouts are less than the lease time

    private static final int THROTTLE_TABLE_QUERIES_MS = 60_000;

    @Getter
    private final ApiContext apiContext;

    private final Map<OperationScope, DataLayout> cachedLayouts = Utils.newConcurrentHashMap();

    private final Map<OperationScope, Long> tableQueries = Utils.newConcurrentHashMap();

    private final Map<String, java.security.KeyPair> tempKeys = Utils.newConcurrentHashMap();

    private final Map<RequestType, Map<String, BigDecimal>> feeLimits = Utils.newConcurrentHashMap();

    @Getter
    private BLSKeyPair blsKeyPair;

    @Getter
    private AtomicBoolean initialized = new AtomicBoolean(false);

    private final List<Runnable> pendingInitialized = new CopyOnWriteArrayList<>();

    private final BulletProofs bulletProofs = createProofs();

    private final ExecutorService apiExecutor = Executors.newCachedThreadPool(new ThreadFactoryBuilder().setNameFormat("WeaveApi-%d").setDaemon(true).build());

    public WeaveApiClientV1(ApiContext apiContext) {
        this.apiContext = apiContext;
    }

    public String getClientVersion() {
        return VERSION;
    }

    protected void initServerKey(String serverPublicKey) {
        apiContext.setServerPublicKey(serverPublicKey);
    }

    protected void initServerSigKey(String publicKey) {
        apiContext.setServerSigKey(publicKey);
    }

    @Override
    public String getUserDID() {
        return "did:weave:" + getClientPublicKey();
    }

    @Override
    public String generateDID(String method) {
        return "did:" + (method != null ? method : "weave") + ":" + Utils.generateUUID();
    }

    @Override
    public void initBlsKeyPair(BLSKeyPair keyPair) {
        blsKeyPair = keyPair;
    }

    protected void keysInit() throws InterruptedException, ExecutionException {
        OperationResult remoteQueryPubKey = publicKey().get();
        String pubKey = remoteQueryPubKey.getStringData();
        initServerKey(pubKey);

        OperationResult remoteQuerySigKey = sigKey().get();
        String sigKey = remoteQuerySigKey.getStringData();
        initServerSigKey(sigKey);

        onInit();
    }

    @Override
    public void whenInitialized(Runnable action) {
        addOnInit(action);
    }

    @Override
    public CompletableFuture<Session> checkSession(Session session, String credentials) {
        if (session != null && session.nearExpiry()) {
            return this.login(session.getOrganization(), session.getAccount(), session.getScopes(), credentials);
        } else {
            CompletableFuture<Session> result;
            result = new CompletableFuture<>();
            result.complete(session);
            return result;
        }
    }

    protected void onInit() {
        if (initialized.compareAndSet(false, true)) {
            synchronized (pendingInitialized) {
                for (Runnable r : pendingInitialized) {
                    r.run();
                }
                pendingInitialized.clear();
            }
        }
    }

    protected void addOnInit(Runnable action) {
        if (initialized.get()) {
            action.run();
        } else {
            pendingInitialized.add(action);
        }
    }

    protected <T> CompletableFuture<T> asyncCall(Callable<T> fn) {
        CompletableFuture<T> future = new CompletableFuture<>();
        apiExecutor.submit(() -> {
            future.complete(fn.call());
            return null;
        });
        return future;
    }

    protected void addAuthParams(Map<String, Object> output, Session session) {
        output.put("x-api-key", session.getApiKey());
        long nonce = session.getNonce().incrementAndGet();
        output.put("x-nonce", Long.toString(nonce));

        String toSign = Utils.getDataToSign(output);
        String signature = Hash.signRequestB64(session.getSecret(), toSign);
        output.put("x-sig", signature);
    }

    protected String signString(String toSign, byte[] iv) {
        return signString(toSign, iv, getApiContext().getServerPublicKey());
    }

    protected String signString(String toSign, byte[] iv, String nodeKey) {
        try {
            KeysInfo key = KeysInfo.fromPublicKey(nodeKey);
            return signString(toSign, iv, key.getKeyPair().getPublic());
        } catch (Exception e) {
            logger.error("Failed parsing key", e);
            return null;
        }
    }

    protected String signString(String toSign, byte[] iv, PublicKey nodeKey) {
        KeyExchange keyExchange = KeysProvider.getInstance();
        SecretKey secretKey = keyExchange.sharedSecret(getApiContext().getClientPrivateKey(), nodeKey, null);
        byte[] signed = keyExchange.encrypt(secretKey, toSign.getBytes(StandardCharsets.UTF_8), getApiContext().getSeed(), iv);
        return Hex.toHexString(signed);
    }

    @Override
    public String getClientPublicKey() {
        return getApiContext().getPublicKey();
    }

    @Override
    public String getServerPublicKey() {
        return getApiContext().getServerEncodedPublicKey();
    }

    @Override
    public void clearFeeLimits() {
        feeLimits.clear();
    }

    @Override
    public void setFeeLimit(RequestType operation, String token, BigDecimal amount) {
        Map<String, BigDecimal> limits = feeLimits.computeIfAbsent(operation, (k) -> Utils.newConcurrentHashMap());
        limits.put(token, amount);
    }

    @Override
    public String getFeeLimits(RequestType operation) {
        Map<String, BigDecimal> limits = feeLimits.get(operation);
        if (limits != null) {
            try {
                Map<String, String> result = new HashMap<>();
                String serialization = Utils.getGson().toJson(limits);
                String toSign = operation.name() + " " + serialization;
                //TODO: Add API key and nonce to signed string
                String signature = KeysProvider.createAccountSignature(apiContext.getSigPrivateKey(), toSign.getBytes(StandardCharsets.UTF_8));

                result.put("limits", serialization);
                result.put("signature", signature);
                return Utils.getGson().toJson(result);
            } catch (Exception e) {
                logger.error("Failed adding signed fee limits", e);
                return null;
            }
        } else {
            return null;
        }
    }

    @Override
    public KeyPair generateKeys() {
        String seed = getApiContext().getSeed() != null ? Hex.toHexString(getApiContext().getSeed()) : null;
        Keys keys = Keys.generateKeys(seed);
        return new KeyPair(keys.getPublicKey(), keys.getPrivateKey());
    }

    //TODO: move to another class, this is definitions storage logic that should not be here
    @SuppressWarnings("unchecked")
    protected DataLayout getTableLayout(Session session, String scope, String table) {
        OperationScope layoutScope = new OperationScope(null, session != null ? session.getOrganization() : null, session != null ? session.getAccount() : null, scope, table);
        DataLayout layout = cachedLayouts.get(layoutScope);

        if (layout != null) {
            return layout;
        } else if (session != null) {
            try {
                long now = System.currentTimeMillis();
                Long prevQuery = tableQueries.get(layoutScope);

                if (prevQuery == null || now - prevQuery > THROTTLE_TABLE_QUERIES_MS) {
                    tableQueries.put(layoutScope, now);

                    OperationResult queryResult;
                    try {
                        queryResult = getTables(session, scope)
                                .whenComplete((r, ex) -> {
                                    if (ex != null) {
                                        logger.error("Failed get tables", ex);
                                    } else if (r.isError()) {
                                        logger.error("Failed get tables" + r.getMessage());
                                    } else {
                                        mapTables(session, scope, r);
                                    }
                                })
                                .get(TABLE_DEF_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    } catch (TimeoutException e) {
                        logger.error("Retrying...");
                    }

                    layout = cachedLayouts.get(layoutScope);

                    if (layout != null) {
                        return layout;
                    } else {
                        OperationResult tableQueryResult = getTableDefinition(session, scope, table)
                                .whenComplete((r, ex) -> {
                                    if (ex != null) {
                                        logger.error("Failed get table", ex);
                                    } else if (r.isError()) {
                                        logger.error("Failed get table" + r.getMessage());
                                    } else {
                                        mapTable(session, scope, r);
                                    }
                                })
                                .get(TABLE_DEF_TIMEOUT_MS, TimeUnit.MILLISECONDS);

                        layout = cachedLayouts.get(layoutScope);
                        if (layout != null) {
                            return layout;
                        } else {
                            logger.error("Invalid table name or no access rights for " + table);
                        }
                    }
                } else {
                    logger.info("Using json serialization. No known table definition, request throttled " + table);
                }

            } catch (Exception e) {
                logger.error("Failed retrieving tables description", e);
            }

            return null;
        } else {
            return null;
        }
    }

    public void addIntegritySignatureIfConfigured(Records records, Session session, String scope, Map<String, Object> request) {
        if (session != null && (session.getIntegrityChecks() == null || !session.getIntegrityChecks())) {
            return;
        }

        // if already signed, Records object has signature. Nothing to do here
        if (records.getIntegrity() != null && !records.getIntegrity().isEmpty()) {
            return;
        }
        computeAndAddIntegritySignature(records, session, scope);
    }

    private void computeAndAddIntegritySignature(Records records, Session session, String scope) {
        try {
            DataLayout layout = getTableLayout(session, scope, records.getTable());
            CopyOnWriteArrayList<Records.IntegrityPair> integrityChecks = new CopyOnWriteArrayList<>();
            Map<String, String> integrityCheck = new TreeMap<>();
            String recordsHash = getHashOfHashes(records, layout);
            integrityCheck.put("recordsHash", recordsHash);
            integrityCheck.put("pubKey", apiContext.getPublicKey());

            if (session != null) {
                synchronized (session.getPrevRecordsData()) {
                    if (session.getPrevRecordsData() != null) {
                        Session.PrevRecordsData prevData = session.getPrevRecordsData(scope, records.getTable());
                        Integer count;
                        if (prevData != null) {
                            count = prevData.getCount() + 1;
                            integrityCheck.put("prevRecordsHash", prevData.getHash());
                            session.setPrevRecordsData(scope, records.getTable(), recordsHash, count);
                        } else {
                            count = 1;
                            session.setPrevRecordsData(scope, records.getTable(), recordsHash, count);
                        }
                        integrityCheck.put("count", String.valueOf(count));
                    }
                }
            }

            String toSign = Utils.getGson().toJson(integrityCheck);
            String signature = KeysProvider.createAccountSignature(apiContext.getSigPrivateKey(), toSign.getBytes(StandardCharsets.UTF_8));

            integrityCheck.put("sig", signature);
            integrityChecks.add(new Records.IntegrityPair(0, integrityCheck));
            records.setIntegrity(integrityChecks);
        } catch (Exception ex) {
            logger.warn("Failed to add data integrity signature", ex);
        }
    }

    /**
     * concatenates hashes of all records & ids of all records; then hashes the concatenation result
     */
    private String getHashOfHashes(Records records, DataLayout layout) {
        String signSecret = apiContext.getSeedHex(); //TODO: use hex seed value rather than the seed string

        StringBuilder idBuffer = new StringBuilder();
        StringBuilder hashesBuffer = new StringBuilder();
        boolean first = true;
        for (List<Object> record : records.getItems()) {
            if (first) {
                first = false;
            } else {
                idBuffer.append(" ");
                hashesBuffer.append("\n");
            }

            List<Object> standardized = Records.standardizeWithoutOwner(record, layout);
            Object id = Records.getRecordId(standardized, layout);
            idBuffer.append(id);

            String data = Utils.getListJsonAdapter().toJson(standardized);
            String hash = Hash.signRequest(signSecret, data);
            hashesBuffer.append(hash);
        }

        String toSign = idBuffer.toString() + "\n" + hashesBuffer;
        return Hash.signRequest(signSecret, toSign);
    }

    private void mapTable(Session session, String scope, OperationResult tableQueryResult) {
        try {
            if (tableQueryResult != null) {
                TableInfo item = Utils.getGson().fromJson(tableQueryResult.getStringData(), TableInfo.class);
                if (item.getLayout() != null) {
                    OperationScope tableLayoutScope = new OperationScope(null, session.getOrganization(), session.getAccount(), scope, item.getName());
                    cachedLayouts.put(tableLayoutScope, item.getLayout());
                }
            }
        } catch (Exception e) {
            logger.error("Failed parsing table structure", e);
        }
    }

    private void mapTables(Session session, String scope, OperationResult queryResult) {
        Map<String, Object> items = Utils.getGson().fromJson(ConvertUtils.convertToString(queryResult.getData()), Map.class);
        Collection<Map<String, Object>> definitions = items.get("tables") instanceof List ? (List<Map<String, Object>>) items.get("tables") : ((Map<String, Map<String, Object>>) items.get("tables")).values();

        if (definitions != null) {
            for (Map<String, Object> item : definitions) {
                addTableDefinition(session, scope, item);
            }
        }
    }

    private void addTableDefinition(Session session, String scope, Map<String, Object> item) {
        String tableName = ConvertUtils.convertToString(item.get("name"));
        DataLayout tableLayout = DataLayout.fromJson(Utils.getGson().toJson(item.get("layout")));

        if (tableName != null && tableLayout != null) {
            OperationScope tableLayoutScope = new OperationScope(null, session.getOrganization(), session.getAccount(), scope, tableName);
            cachedLayouts.put(tableLayoutScope, tableLayout);
        } else {
            logger.warn("Invalid definition received" + Utils.getGson().toJson(item));
        }
    }


    @Override
    public String sign(String data) {
        try {
            return KeysProvider.createAccountSignature(apiContext.getSigPrivateKey(), data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            logger.error("Failed verifying signature", e);
            return null;
        }
    }

    @Override
    public boolean verifySignature(PublicKey publicKey, String signature, String data) {
        try {
            PublicKey sigKey = publicKey != null ? publicKey : apiContext.getServerSigKey();
            return KeysProvider.verifyAccountSignature(sigKey, signature, data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            logger.error("Failed verifying signature", e);
            return false;
        }
    }

    @Override
    public boolean verifyLineageSignature(String signature, String inputsHash, String computeHash, String paramsHash, String data) {
        try {
            String toSign = (inputsHash != null ? inputsHash + "\n" : "")
                    + (computeHash != null ? computeHash + "\n" : "")
                    + (paramsHash != null ? paramsHash + "\n" : "")
                    + data;
            return KeysProvider.verifyAccountSignature(getApiContext().getServerSigKey(), signature, toSign.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            logger.error("Failed verifying signature", e);
            return false;
        }
    }

    @Override
    public boolean verifyLineageSignatureTs(String signature, String timestamp, String inputsHash, String computeHash, String paramsHash, String data) {
        try {
            String toSign = timestamp + "\n"
                    + (inputsHash != null ? inputsHash + "\n" : "")
                    + (computeHash != null ? computeHash + "\n" : "")
                    + (paramsHash != null ? paramsHash + "\n" : "")
                    + data;
            return KeysProvider.verifyAccountSignature(getApiContext().getServerSigKey(), signature, toSign.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            logger.error("Failed verifying signature", e);
            return false;
        }
    }

    @Override
    public boolean verifyMerkleHash(String tree, String hash, String digest) {
        MerkleTree merkleTree = MerkleTree.createTree(tree, digest);

        return merkleTree.verifyHash(hash);
    }

    @Override
    public boolean verifyMerkleProof(String recordHash, String proof, String rootHash, String digest) {
        return MerkleTree.verifyProof(recordHash, proof, rootHash, digest);
    }

    @Override
    public OperationResult mimcHash(String data, Integer rounds, Integer seed, boolean compress) {
        AtomicInteger depth = new AtomicInteger(0);
        AtomicInteger length = new AtomicInteger(0);
        Scalar hash = MiMC.mimcHash(data.getBytes(StandardCharsets.UTF_8), seed, rounds, depth, length, compress);

        Map<String, Object> result = new HashMap<>();
        result.put("hash", Base58.encode(hash.toByteArray()));
        result.put("length", length.get());

        return new Success(null, result);
    }

    @Override
    public String hashRecord(List<Object> row, byte[] salt, String digest) {
        return SigUtils.encodeForSigning(row, salt, digest);
    }

    @Override
    public String zkDataProof(String data, byte[] challenge) {
        try {
            String digest = null; //use configured default
            byte[] dataHash = Hash.signString(challenge, data, digest);
            if (dataHash != null) {
                return SchnorrNIZK.prove(SigUtils.scalarFromBigInteger(new BigInteger(dataHash))).toBase58();
            } else {
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed generating proof", e);
            return null;
        }
    }

    @Override
    public boolean verifyDataProof(String data, byte[] challenge, String transcript) {
        try {
            String digest = null; //use configured default
            byte[] dataHash = Hash.signString(challenge, data, digest);
            return dataHash != null && SchnorrNIZK.verify(SigUtils.scalarFromBigInteger(new BigInteger(dataHash)), SchnorrNIZK.Transcript.fromBase58(transcript));
        } catch (Exception e) {
            logger.error("Failed verifying proof", e);
            return false;
        }
    }

    @Override
    public String zkDataProof(Records data, byte[] challenge) {
        try {
            String digest = null; //use configured default
            byte[] recordsHash = Hash.signBytes(challenge, SigUtils.encodeForSigning(data, challenge, digest), digest);
            if (recordsHash != null) {
                return SchnorrNIZK.prove(SigUtils.scalarFromBigInteger(new BigInteger(recordsHash))).toBase58();
            } else {
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed signing", e);
        }
        return null;
    }

    @Override
    public boolean verifyDataProof(Records data, byte[] challenge, String transcript) {
        try {
            String digest = null; //use configured default
            byte[] recordsHash = Hash.signBytes(challenge, SigUtils.encodeForSigning(data, challenge, digest), digest);
            return recordsHash != null && SchnorrNIZK.verify(SigUtils.scalarFromBigInteger(new BigInteger(recordsHash)), SchnorrNIZK.Transcript.fromBase58(transcript));
        } catch (Exception e) {
            logger.error("Failed verifying proof", e);
            return false;
        }
    }

    @Override
    public CompletableFuture<OperationResult> zkProof(Object value, String gadgetType, String params, ZKOptions options) {
        CompletableFuture<OperationResult> op = new CompletableFuture<>();

        try {
            PedersenCommitment pc = options.getCommitment() != null ? PedersenCommitment.from(options.getCommitment()) : PedersenCommitment.getDefault();
            Proof proof = bulletProofs.generate(gadgetType, value, params, pc, options.getGenerators());
            String encoded = Base58.encode(proof.serialize());
            op.complete(new Success(null, encoded));
        } catch (Exception e) {
            logger.error("Failed building proof", e);
            op.complete(new AccessError(null, e.toString()));
        }

        return op;
    }

    @Override
    public boolean verifyZkProof(String proof, String gadgetType, String params) {
        return verifyZkProof(proof, gadgetType, params, null, null);
    }

    @Override
    public boolean verifyZkProof(String proof, String gadgetType, String params, String commitment, Integer nGenerators) {
        try {
            PedersenCommitment pc = commitment != null ? PedersenCommitment.from(commitment) : PedersenCommitment.getDefault();
            return bulletProofs.verify(gadgetType, params, proof, pc, nGenerators);
        } catch (Exception e) {
            logger.error("Failed veryfing proof", e);
        }

        return false;
    }


    protected Map<String, Object> buildProxyLoginParams(String node, String organization, String account, String scopes) {
        String toSign = organization + "\n" + getClientPublicKey() + "\n" + scopes;
        byte[] iv = KeysProvider.generateIV();
        String signature = signString(toSign, iv, node);

        KeyExchange keyExchange = KeysProvider.getInstance();
        java.security.KeyPair tempKey = KeysProvider.getInstance().generateKeys();
        String pubKey = Base64.encodeBase64String(tempKey.getPublic().getEncoded());
        tempKeys.put(pubKey, tempKey);

        KeysInfo nodeKey = KeysInfo.fromPublicKey(node);
        byte[] iv2 = KeysProvider.generateIV();
        SecretKey secretKey = keyExchange.sharedSecret(tempKey.getPrivate(), nodeKey.getKeyPair().getPublic(), null);

        Map<String, Object> encParams = new HashMap<>();
        encParams.put("account", account);
        encParams.put("scopes", scopes);
        encParams.put("signature", signature);
        encParams.put("x-key", getClientPublicKey());
        encParams.put("x-sig-key", KeysProvider.derivePublicSigKey(tempKey.getPrivate()));
        encParams.put("x-rsa-key", KeysProvider.derivePublicRSAKey(tempKey.getPrivate()));
        if (blsKeyPair != null && blsKeyPair.getPublicKey() != null) {
            encParams.put("x-bls-key", Base58.encode(blsKeyPair.getPublicKey()));
        }
        encParams.put("x-iv", Hex.toHexString(iv));
        encParams.put("x-pk", pubKey);
        encParams.put("type", RequestType.login.name());
        addDelegateSignature(encParams);

        byte[] data = Utils.getGson().toJson(encParams).getBytes(StandardCharsets.UTF_8);
        byte[] enc = keyExchange.encrypt(secretKey, data, getApiContext().getSeed(), iv2);

        Map<String, Object> params = new HashMap<>();

        params.put("organization", organization);
        params.put("scopes", scopes);

        params.put("type", RequestType.proxy_login.name());
        params.put("node", node);
        params.put("msg", Base64.encodeBase64String(enc));
        params.put("x-iv", Hex.toHexString(iv2));
        params.put("x-pk", pubKey);
        return params;
    }

    protected void addDelegateSignature(Map encParams) {
        try {
            String delegate = getServerPublicKey(); //TODO: review, maybe add expiration, link to a specific server api key
            String delegateSignature = KeysProvider.createAccountSignature(apiContext.getSigPrivateKey(), delegate.getBytes(StandardCharsets.UTF_8));
            encParams.put("x-dlg-sig", delegateSignature);

            String ownSignature = KeysProvider.createAccountSignature(apiContext.getSigPrivateKey(), getClientPublicKey().getBytes(StandardCharsets.UTF_8));
            encParams.put("x-own-sig", ownSignature);
        } catch (Exception e) {
            logger.error("Failed adding delegate signature", e);
        }
    }

    @Override
    public boolean proxyEncrypt(Session session, String scope, String table, List<List<Object>> data, List<String> readerPublicKeys, DataLayout layout) {
        try {
            EncryptionConfig encryptionConfig = PREHelper.encryptRecords(layout, data);

            for (String readerPublicKey : readerPublicKeys) {
                OperationResult readerBlsKey = blsKey(readerPublicKey).get();
                byte[] readerPubKey = Base58.decode(readerBlsKey.getStringData());
                ProxyEncryptedData pre = PREHelper.prepareForProxy(encryptionConfig.getSecretKey(), readerPubKey);
                proxyEncryptSecret(session, scope, table, pre).get();
            }

            return true;
        } catch (Exception e) {
            logger.error("Failed proxy encrypt", e);
            return false;
        }
    }

    @Override
    public boolean proxyDecrypt(Session session, List<Map<String, Object>> data, String pre, BLSKeyPair readerKeyPair, DataLayout layout) {
        try {
            ClientEncryptedData preData = ClientEncryptedData.fromJson(pre);
            byte[] decoded = PREHelper.decode(preData.getEncoded(), readerKeyPair.getSecretKey(), preData.getProxySignPubKey());
            EncryptionConfig decryptionConfig = new EncryptionConfig(EncryptionConfig.AES, Base64.encodeBase64String(decoded), null);
            EncryptionHelper.decryptRecords(layout, decryptionConfig, data);
            return true;
        } catch (Exception e) {
            logger.error("Failed proxy decrypt", e);
            return false;
        }
    }

    protected Map<String, Object> encryptProxyParams(Session session, String url, Map<String, Object> args, String node, String pubKey) {
        KeyExchange keyExchange = KeysProvider.getInstance();
        java.security.KeyPair tempKey = tempKeys.get(pubKey);

        KeysInfo nodeKey = KeysInfo.fromPublicKey(node);
        SecretKey secretKey = keyExchange.sharedSecret(tempKey.getPrivate(), nodeKey.getKeyPair().getPublic(), null);

        String type = url.contains("/") ? url.substring(url.lastIndexOf("/") + 1) : url;
        args.put("type", type);
        args.put("x-source-pk", apiContext.getPublicKey());

        String reqBody = Utils.getGson().toJson(args);

        Map<String, Object> encParams = new HashMap<>();
        encParams.put("body", reqBody);
        encParams.put("x-api-key", session.getApiKey());
        String nonce = Long.toString(session.getNonce().incrementAndGet());
        encParams.put("x-nonce", nonce);

        String requestType = url.contains("/") ? url.substring(url.lastIndexOf("/", url.lastIndexOf("/") - 1)) : url;
        String toSign = requestType
                + "\n" + session.getApiKey()
                + "\n" + nonce
                + "\n" + (reqBody.isEmpty() ? "{}" : reqBody);
        String signature = Hash.signRequestB64(session.getSecret(), toSign);
        encParams.put("x-sig", signature);

        byte[] data = Utils.getGson().toJson(encParams).getBytes(StandardCharsets.UTF_8);
        byte[] iv2 = KeysProvider.generateIV();
        byte[] enc = keyExchange.encrypt(secretKey, data, getApiContext().getSeed(), iv2);

        Map<String, Object> params = new HashMap<>();

        params.put("organization", session.getOrganization());
        params.put("scopes", session.getScopes());

        params.put("type", url.substring(url.lastIndexOf("/") + 1));
        params.put("node", node);
        params.put("msg", Base64.encodeBase64String(enc));
        params.put("x-iv", Hex.toHexString(iv2));
        params.put("x-pk", pubKey);

        return params;
    }

    @SuppressWarnings("unchecked")
    protected String decryptProxyParams(OperationResult result) {
        Object source = result.getData();
        Map<String, Object> reply = source instanceof Map ? (Map)source : Utils.getGson().fromJson(source.toString(), Map.class);

        KeyExchange keyExchange = KeysProvider.getInstance();

        String pubKey = reply.get("x-pk").toString();
        java.security.KeyPair keyPair = tempKeys.get(pubKey);

        byte[] kmsg = reply.get("x-kmsg") != null ? Base64.decodeBase64(reply.get("x-kmsg").toString()) : null;

        if (keyPair != null) {
            KeysInfo nodeKey = KeysInfo.fromPublicKey(reply.get("x-src").toString());

            SecretKey secretKey = keyExchange.sharedSecret(keyPair.getPrivate(), nodeKey.getKeyPair().getPublic(), kmsg);

            byte[] iv = Hex.decode(reply.get("x-iv").toString());
            byte[] data = keyExchange.decrypt(secretKey, Base64.decodeBase64(reply.get("msg").toString()), getApiContext().getSeed(), iv);
            String decoded = new String(data, StandardCharsets.UTF_8).replaceAll("\0", "");

            return decoded;
        } else if (Objects.equals(pubKey, getClientPublicKey())) {
            KeysInfo nodeKey = KeysInfo.fromPublicKey(reply.get("x-src").toString());
            SecretKey secretKey = keyExchange.sharedSecret(getApiContext().getClientPrivateKey(), nodeKey.getKeyPair().getPublic(), kmsg);

            byte[] iv = Hex.decode(reply.get("x-iv").toString());
            byte[] data = keyExchange.decrypt(secretKey, Base64.decodeBase64(reply.get("msg").toString()), getApiContext().getSeed(), iv);
            String decoded = new String(data, StandardCharsets.UTF_8).replaceAll("\0", "");

            return decoded;
        } else {
            logger.debug("Unknown public key " + pubKey + ", skipping message, not the recipient");
            return null;
        }
    }

    @Override
    public CompletableFuture<OperationResult> file(String file, Consumer<byte[]> callback) {
        throw new IllegalArgumentException("Not implemented");
    }

    @Override
    public CompletableFuture<OperationResult> hashCheckpoint(Session session) {
        return hashCheckpoint(session, null);
    }

    @Override
    public CompletableFuture<OperationResult> getImage(String image, Session session, Consumer<byte[]> callback) {
        throw new IllegalArgumentException("Not implemented");
    }

    @Override
    public Map<String, Object> blindMessage(String signerPublicKey, byte[] message) {
        try {
            RSAKeyParameters publicKey = KeysProvider.decodeRSAPublicKey(Base58.decode(signerPublicKey));

            RSABlindingFactorGenerator generator = new RSABlindingFactorGenerator();
            generator.init(publicKey);

            BigInteger factor = generator.generateBlindingFactor();
            RSABlindingParameters params = new RSABlindingParameters(publicKey, factor);

            RSABlindingEngine engine = new RSABlindingEngine();
            engine.init(false, params);

            PSSSigner signer = new PSSSigner(new RSABlindingEngine(), new SHA256Digest(), KeysProvider.PSS_SALT_LEN);
            signer.init(true, params);
            signer.update(message, 0, message.length);

            Map<String, Object> result = new HashMap<>();
            result.put("factor", Base58.encode(params.getBlindingFactor().toByteArray()));
            result.put("blinded", Base58.encode(signer.generateSignature()));
            return result;
        } catch (Exception e) {
            logger.error("Failed generating signature", e);
            return null;
        }
    }

    @Override
    public String blindSign(String signerPublicKey, String signature, BigInteger factor) {
        try {
            byte[] blinded = Base58.decode(signature);
            RSAKeyParameters publicKey = KeysProvider.decodeRSAPublicKey(Base58.decode(signerPublicKey));
            RSABlindingParameters params = new RSABlindingParameters(publicKey, factor);
            RSABlindingEngine blindingEngine = new RSABlindingEngine();
            blindingEngine.init(false, params);
            return Base58.encode(blindingEngine.processBlock(blinded, 0, blinded.length));
        } catch (Exception e) {
            logger.error("Failed generating signature", e);
            return null;
        }
    }

    @Override
    public boolean verifyBlindSignature(String signerPublicKey, byte[] message, String signature) {
        try {
            RSAKeyParameters publicKey = KeysProvider.decodeRSAPublicKey(Base58.decode(signerPublicKey));
            PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), KeysProvider.PSS_SALT_LEN);
            signer.init(false, publicKey);
            signer.update(message, 0, message.length);
            return signer.verifySignature(Base58.decode(signature));
        } catch (Exception e) {
            logger.error("Failed verifying signature", e);
            return false;
        }
    }

    @Override
    public OperationResult tokenUpload(String apiUrl, String token, String scope, Records records, WriteOptions options) {
        try (CloseableHttpClient httpClient = HttpClients.custom().build()) {
            String url = apiUrl + (apiUrl.endsWith("/") ? "" : "/") + "upload";

            HttpPost request = new HttpPost(url);
            request.addHeader(HTTP.CONTENT_ENCODING, "gzip");
            request.addHeader(HTTP.USER_AGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36");
            request.addHeader("accept", "application/json");
            request.addHeader(HttpApiClient.AUTH_HEADER, token);

            Map<String, Object> params = new TreeMap<>();
            params.put("scope", scope);
            params.put("table", records.getTable());

            addIntegritySignatureIfConfigured(records, null, scope, params);

            //DataLayout layout = getTableLayout(null, scope, records.getTable());
            //ContentEncoder encoder = Encoding.getJsonContentEncoder();
            //params.put("records", encoder.encode(records, layout));
            params.put("items", Utils.getGson().toJson(records.getItems()));

            if (options != null) {
                params.put("options", Utils.getWriteOptionsJsonAdapter().toJson(options));
            }

            request.setEntity(new StringEntity(Utils.getGson().toJson(params)));

            CloseableHttpResponse response = httpClient.execute(request);

            int statusCode = response.getStatusLine().getStatusCode();

            byte[] reply = response.getEntity().getContent().readAllBytes();
            String result = new String(reply, StandardCharsets.UTF_8);
            return new Success(null, result);
        } catch (Exception e) {
            logger.error("Failed token upload", e);
            return new AccessError(null, e.toString());
        }
    }

    public static BulletProofs createProofs() {
        final BulletProofs bulletProofs = new BulletProofs();
        Gadgets.registerGadgets(bulletProofs);
        return bulletProofs;
    }
}
