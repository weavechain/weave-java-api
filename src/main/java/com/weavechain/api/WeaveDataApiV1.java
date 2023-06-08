package com.weavechain.api;

import com.weavechain.api.auth.BLSKeyPair;
import com.weavechain.api.auth.KeyPair;
import com.weavechain.api.client.WeaveAuthApi;
import com.weavechain.api.pre.ProxyEncryptedData;
import com.weavechain.api.session.Session;
import com.weavechain.core.consensus.ConsensusMessage;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.filter.Filter;
import com.weavechain.core.data.Records;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.file.FileFormat;
import com.weavechain.core.operations.*;

import com.weavechain.core.requests.RequestType;
import com.weavechain.core.utils.CompletableFuture;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public interface WeaveDataApiV1 extends WeaveAuthApi {

    String getClientPublicKey();

    KeyPair generateKeys();

    void initBlsKeyPair(BLSKeyPair keyPair);

    CompletableFuture<OperationResult> version();

    CompletableFuture<OperationResult> ping();

    CompletableFuture<OperationResult> publicKey();

    CompletableFuture<OperationResult> sigKey();

    CompletableFuture<OperationResult> sigKey(String account);

    CompletableFuture<OperationResult> rsaKey();

    CompletableFuture<OperationResult> rsaKey(String account);

    CompletableFuture<OperationResult> blsKey();

    CompletableFuture<OperationResult> blsKey(String account);

    CompletableFuture<OperationResult> status(Session session);

    CompletableFuture<OperationResult> createTable(Session session, String scope, String table, CreateOptions options);

    CompletableFuture<OperationResult> dropTable(Session session, String scope, String table, DropOptions options);

    CompletableFuture<OperationResult> write(Session session, String scope, Records records, WriteOptions options);

    CompletableFuture<OperationResult> read(Session session, String scope, String table, Filter filter, ReadOptions options);

    CompletableFuture<OperationResult> count(Session session, String scope, String table, Filter filter, ReadOptions options);

    CompletableFuture<OperationResult> delete(Session session, String scope, String table, Filter filter, DeleteOptions options);

    CompletableFuture<OperationResult> hashes(Session session, String scope, String table, Filter filter, ReadOptions options);

    CompletableFuture<OperationResult> downloadTable(Session session, String scope, String table, Filter filter, FileFormat format, ReadOptions options);

    CompletableFuture<OperationResult> downloadDataset(Session session, String did, ReadOptions options);

    CompletableFuture<OperationResult> publishDataset(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String scope, String table, Filter filter, FileFormat format, BigDecimal price, String token, Long pageorder, PublishDatasetOptions options);

    CompletableFuture<OperationResult> enableProduct(Session session, String did, String productType, Boolean active);

    CompletableFuture<OperationResult> runTask(Session session, String did, ComputeOptions options);

    CompletableFuture<OperationResult> publishTask(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String task, BigDecimal price, String token, Long pageorder, PublishTaskOptions options);

    CompletableFuture<OperationResult> subscribe(Session session, String scope, String table, Filter filter, SubscribeOptions options, BiConsumer<String, Records> onData);

    CompletableFuture<OperationResult> unsubscribe(Session session, String subscriptionId);

    CompletableFuture<OperationResult> compute(Session session, String image, ComputeOptions options);

    CompletableFuture<OperationResult> getImage(String image, Session session, Consumer<byte[]> callback);

    CompletableFuture<OperationResult> flearn(Session session, String image, FLOptions options);

    CompletableFuture<OperationResult> splitLearn(Session session, String image, SplitLearnOptions options);

    CompletableFuture<OperationResult> heGetInputs(Session session, List<Object> datasources, List<Object> args);

    CompletableFuture<OperationResult> heGetOutputs(Session session, String encoded, List<Object> args);

    CompletableFuture<OperationResult> heEncode(Session session, List<Object> items);

    CompletableFuture<OperationResult> pluginCall(Session session, String plugin, String request, Map<String, Object> args, int timeoutSec);

    CompletableFuture<OperationResult> file(String file, Consumer<byte[]> callback);

    CompletableFuture<OperationResult> mpc(Session session, String scope, String table, String algo, List<String> fields, Filter filter, MPCOptions options);

    // start: move to private API
    CompletableFuture<OperationResult> mpcInitProtocol(Session session, String computationId, int nodeIndex, String scope, String table, String algo, List<String> fields, Filter filter, Map<String, Integer> indexedPeers, MPCOptions options);

    CompletableFuture<OperationResult> mpcProtocol(Session session, String computationId, String message);
    // end

    CompletableFuture<OperationResult> proxyEncryptSecret(Session session, String scope, String table, ProxyEncryptedData pre);

    CompletableFuture<OperationResult> proxyReEncryptSecret(Session session, String scope, String table);

    CompletableFuture<OperationResult> blindSignature(Session session, String blinded);

    boolean proxyEncrypt(Session session, String scope, String table, List<List<Object>> data, List<String> readerPublicKeys, DataLayout layout);

    boolean proxyDecrypt(Session session, List<Map<String, Object>> data, String pre, BLSKeyPair readerKeyPair, DataLayout layout);

    CompletableFuture<OperationResult> storageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options);

    CompletableFuture<OperationResult> zkStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options);

    CompletableFuture<OperationResult> merkleTree(Session session, String scope, String table, Filter filter, String salt, ReadOptions options);

    CompletableFuture<OperationResult> merkleProof(Session session, String scope, String table, String hash);

    CompletableFuture<OperationResult> zkMerkleTree(Session session, String scope, String table, Filter filter, String salt, Integer rounds, Integer seed, ZKOptions options);

    CompletableFuture<OperationResult> rootHash(Session session, String scope, String table);

    CompletableFuture<OperationResult> verifyDataSignature(Session session, String signer, String signature, String data);

    OperationResult mimcHash(String data, Integer rounds, Integer seed, boolean compress);

    boolean verifyMerkleHash(String tree, String hash, String digest);

    boolean verifyMerkleProof(String recordHash, String proof, String rootHash, String digest);

    String hashRecord(List<Object> row, byte[] salt, String digest);

    CompletableFuture<OperationResult> broadcast(Session session, ConsensusMessage message);

    String sign(String data);

    boolean verifySignature(PublicKey publicKey, String signature, String data);

    boolean verifyLineageSignature(String signature, String inputsHash, String computeHash, String paramsHash, String data);

    boolean verifyLineageSignatureTs(String signature, String timestamp, String inputsHash, String computeHash, String paramsHash, String data);

    String zkDataProof(String data, byte[] challenge);

    boolean verifyDataProof(String data, byte[] challenge, String transcript);

    String zkDataProof(Records records, byte[] challenge);

    boolean verifyDataProof(Records data, byte[] challenge, String transcript);

    CompletableFuture<OperationResult> zkProof(Session session, String scope, String table, String gadgetType, String params, List<String> fields, Filter filter, ZKOptions options);

    //this generates a data proof remotely
    CompletableFuture<OperationResult> zkDataProof(Session session, String gadgetType, String params, List<Object> values, ZKOptions options);

    CompletableFuture<OperationResult> proofsLastHash(Session session, String scope, String table);

    CompletableFuture<OperationResult> updateProofs(Session session, String scope, String table);

    //this generates a proof locally
    CompletableFuture<OperationResult> zkProof(Object value, String gadgetType, String params, ZKOptions options);

    boolean verifyZkProof(String proof, String gadgetType, String params);

    boolean verifyZkProof(String proof, String gadgetType, String params, String commitment, Integer nGenerators);

    CompletableFuture<OperationResult> thresholdSigPubkeyRound1(Session session, String scope, String table, String uuid, String message, ThresholdSigOptions options);

    CompletableFuture<OperationResult> thresholdSigRound2(Session session, String scope, String table, String uuid, String message, byte[] scalarK, ThresholdSigOptions options);

    CompletableFuture<OperationResult> readThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options);

    CompletableFuture<OperationResult> setThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options);

    CompletableFuture<OperationResult> uploadApi(Session session, Map<String, Object> params);

    CompletableFuture<OperationResult> withdraw(Session session, String token, BigInteger amount);

    CompletableFuture<OperationResult> withdrawAuthorize(Session session, String token, String address);

    OperationResult tokenUpload(String apiUrl, String token, String scope, Records records, WriteOptions options);

    void clearFeeLimits();

    void setFeeLimit(RequestType operation, String token, BigDecimal amount);

    String getFeeLimits(RequestType operation);

    Map<String, Object> blindMessage(String signerPublicKey, byte[] message);

    String blindSign(String signerPublicKey, String signature, BigInteger factor);

    boolean verifyBlindSignature(String signerPublicKey, byte[] message, String signature);
}
