package com.weavechain.api;

import com.weavechain.api.auth.BLSKeyPair;
import com.weavechain.api.auth.KeyPair;
import com.weavechain.api.client.ApiClientV1;
import com.weavechain.api.client.WeaveApiClientV1;
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
import lombok.Getter;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;


public class AggregatedApiClientV1 implements ApiClientV1 {

    @Getter
    private final WeaveApiClientV1 apiClient;

    public AggregatedApiClientV1(WeaveApiClientV1 apiClient) {
        this.apiClient = apiClient;
    }

    @Override
    public boolean init() {
        return apiClient.init();
    }

    @Override
    public void whenInitialized(Runnable action) {
        apiClient.whenInitialized(action);
    }

    //data interface
    @Override
    public String getClientPublicKey() {
        return apiClient.getClientPublicKey();
    }

    @Override
    public String getServerPublicKey() {
        return apiClient.getServerPublicKey();
    }

    @Override
    public void clearFeeLimits() {
        apiClient.clearFeeLimits();
    }

    @Override
    public void setFeeLimit(RequestType operation, String token, BigDecimal amount) {
        apiClient.setFeeLimit(operation, token, amount);
    }

    @Override
    public String getFeeLimits(RequestType operation) {
        return apiClient.getFeeLimits(operation);
    }

    @Override
    public KeyPair generateKeys() {
        return apiClient.generateKeys();
    }

    @Override
    public void initBlsKeyPair(BLSKeyPair keyPair) {
        apiClient.initBlsKeyPair(keyPair);
    }

    @Override
    public CompletableFuture<OperationResult> version() {
        return apiClient.version();
    }

    @Override
    public CompletableFuture<OperationResult> ping() {
        return apiClient.ping();
    }

    @Override
    public CompletableFuture<OperationResult> publicKey() {
        return apiClient.publicKey();
    }

    @Override
    public CompletableFuture<OperationResult> sigKey() {
        return apiClient.sigKey();
    }

    @Override
    public CompletableFuture<OperationResult> sigKey(String account) {
        return apiClient.sigKey(account);
    }

    @Override
    public CompletableFuture<OperationResult> rsaKey() {
        return apiClient.rsaKey();
    }

    @Override
    public CompletableFuture<OperationResult> rsaKey(String account) {
        return apiClient.rsaKey(account);
    }

    @Override
    public CompletableFuture<OperationResult> blsKey() {
        return apiClient.blsKey();
    }

    @Override
    public CompletableFuture<OperationResult> blsKey(String account) {
        return apiClient.blsKey(account);
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes) {
        return apiClient.login(organization, account, scopes, null);
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes, String credentials) {
        return apiClient.login(organization, account, scopes, credentials);
    }

    @Override
    public CompletableFuture<Session> proxyLogin(String node, String organization, String account, String scopes) {
        return apiClient.proxyLogin(node, organization, account, scopes);
    }

    @Override
    public CompletableFuture<OperationResult> logout(Session session) {
        return apiClient.logout(session);
    }

    @Override
    public CompletableFuture<Session> checkSession(Session session, String credentials) {
        return apiClient.checkSession(session, credentials);
    }

    @Override
    public CompletableFuture<OperationResult> terms(Session session, TermsOptions options) {
        return apiClient.terms(session, options);
    }

    @Override
    public CompletableFuture<OperationResult> status(Session session) {
        return apiClient.status(session);
    }

    @Override
    public CompletableFuture<OperationResult> createTable(Session session, String scope, String table, CreateOptions options) {
        return apiClient.createTable(session, scope, table, options);
    }

    @Override
    public CompletableFuture<OperationResult> dropTable(Session session, String scope, String table, DropOptions options) {
        return apiClient.dropTable(session, scope, table, options);
    }

    @Override
    public CompletableFuture<OperationResult> write(Session session, String scope, Records records, WriteOptions options) {
        return apiClient.write(session, scope, records, options);
    }

    @Override
    public CompletableFuture<OperationResult> read(Session session, String scope, String table, Filter filter, ReadOptions options) {
        return apiClient.read(session, scope, table, filter, options);
    }

    @Override
    public CompletableFuture<OperationResult> count(Session session, String scope, String table, Filter filter, ReadOptions options) {
        return apiClient.count(session, scope, table, filter, options);
    }

    @Override
    public CompletableFuture<OperationResult> delete(Session session, String scope, String table, Filter filter, DeleteOptions options) {
        return apiClient.delete(session, scope, table, filter, options);
    }

    @Override
    public CompletableFuture<OperationResult> hashes(Session session, String scope, String table, Filter filter, ReadOptions options) {
        return apiClient.hashes(session, scope, table, filter, options);
    }

    @Override
    public CompletableFuture<OperationResult> downloadTable(Session session, String scope, String table, Filter filter, FileFormat format, ReadOptions options) {
        return apiClient.downloadTable(session, scope, table, filter, format, options);
    }

    @Override
    public CompletableFuture<OperationResult> downloadDataset(Session session, String did, ReadOptions options) {
        return apiClient.downloadDataset(session, did, options);
    }

    @Override
    public CompletableFuture<OperationResult> publishDataset(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String scope, String table, Filter filter, FileFormat format, BigDecimal price, String token, Long pageorder, PublishDatasetOptions options) {
        return apiClient.publishDataset(session, did, name, description, license, metadata, weave, fullDescription, logo, category, scope, table, filter, format, price, token, pageorder, options);
    }

    @Override
    public CompletableFuture<OperationResult> enableProduct(Session session, String did, String productType, Boolean active) {
        return apiClient.enableProduct(session, did, productType, active);
    }

    @Override
    public CompletableFuture<OperationResult> runTask(Session session, String did, ComputeOptions options) {
        return apiClient.runTask(session, did, options);
    }

    @Override
    public CompletableFuture<OperationResult> publishTask(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String task, BigDecimal price, String token, Long pageorder, PublishTaskOptions options) {
        return apiClient.publishTask(session, did, name, description, license, metadata, weave, fullDescription, logo, category, task, price, token, pageorder, options);
    }

    @Override
    public CompletableFuture<OperationResult> subscribe(Session session, String scope, String table, Filter filter, SubscribeOptions options, BiConsumer<String, Records> onData) {
        return apiClient.subscribe(session, scope, table, filter, options, onData);
    }

    @Override
    public CompletableFuture<OperationResult> unsubscribe(Session session, String subscriptionId) {
        return apiClient.unsubscribe(session, subscriptionId);
    }

    @Override
    public CompletableFuture<OperationResult> compute(Session session, String image, ComputeOptions options) {
        return apiClient.compute(session, image, options);
    }

    @Override
    public CompletableFuture<OperationResult> getImage(String image, Session session, Consumer<byte[]> callback) {
        return apiClient.getImage(image, session, callback);
    }

    @Override
    public CompletableFuture<OperationResult> flearn(Session session, String image, FLOptions options) {
        return apiClient.flearn(session, image, options);
    }

    @Override
    public CompletableFuture<OperationResult> splitLearn(Session session, String image, SplitLearnOptions options) {
        return apiClient.splitLearn(session, image, options);
    }

    @Override
    public CompletableFuture<OperationResult> heGetInputs(Session session, List<Object> datasources, List<Object> args) {
        return apiClient.heGetInputs(session, datasources, args);
    }

    @Override
    public CompletableFuture<OperationResult> heGetOutputs(Session session, String encoded, List<Object> args) {
        return apiClient.heGetOutputs(session, encoded, args);
    }

    @Override
    public CompletableFuture<OperationResult> storageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        return apiClient.storageProof(session, scope, table, filter, challenge, options);
    }

    @Override
    public CompletableFuture<OperationResult> zkStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        return apiClient.zkStorageProof(session, scope, table, filter, challenge, options);
    }

    @Override
    public CompletableFuture<OperationResult> merkleTree(Session session, String scope, String table, Filter filter, String salt, ReadOptions options) {
        return apiClient.merkleTree(session, scope, table, filter, salt, options);
    }

    @Override
    public CompletableFuture<OperationResult> merkleProof(Session session, String scope, String table, String hash) {
        return apiClient.merkleProof(session, scope, table, hash);
    }

    @Override
    public CompletableFuture<OperationResult> zkMerkleTree(Session session, String scope, String table, Filter filter, String salt, Integer rounds, Integer seed, ZKOptions options) {
        return apiClient.zkMerkleTree(session, scope, table, filter, salt, rounds, seed, options);
    }

    @Override
    public CompletableFuture<OperationResult> rootHash(Session session, String scope, String table) {
        return apiClient.rootHash(session, scope, table);
    }

    @Override
    public CompletableFuture<OperationResult> verifyDataSignature(Session session, String signer, String signature, String data) {
        return apiClient.verifyDataSignature(session, signer, signature, data);
    }

    @Override
    public boolean verifyMerkleHash(String tree, String hash, String digest) {
        return apiClient.verifyMerkleHash(tree, hash, digest);
    }

    @Override
    public boolean verifyMerkleProof(String recordHash, String proof, String rootHash, String digest) {
        return apiClient.verifyMerkleProof(recordHash, proof, rootHash, digest);
    }

    @Override
    public OperationResult mimcHash(String data, Integer rounds, Integer seed, boolean compress) {
        return apiClient.mimcHash(data, rounds, seed, compress);
    }

    @Override
    public String hashRecord(List<Object> row, byte[] salt, String digest) {
        return apiClient.hashRecord(row, salt, digest);
    }

    @Override
    public CompletableFuture<OperationResult> heEncode(Session session, List<Object> items) {
        return apiClient.heEncode(session, items);
    }

    @Override
    public CompletableFuture<OperationResult> mpc(Session session, String scope, String table, String algo, List<String> fields, Filter filter, MPCOptions options) {
        return apiClient.mpc(session, scope, table, algo, fields, filter, options);
    }

    @Override
    public CompletableFuture<OperationResult> file(String file, Consumer<byte[]> callback) {
        return apiClient.file(file, callback);
    }

    @Override
    public CompletableFuture<OperationResult> pluginCall(Session session, String plugin, String request, Map<String, Object> args, int timeoutSec) {
        return apiClient.pluginCall(session, plugin, request, args, timeoutSec);
    }

    @Override
    public CompletableFuture<OperationResult> mpcInitProtocol(Session session, String computationId, int nodeIndex, String scope, String table, String algo, List<String> fields, Filter filter, Map<String, Integer> indexedPeers, MPCOptions options) {
        return apiClient.mpcInitProtocol(session, computationId, nodeIndex, scope, table, algo, fields, filter, indexedPeers, options);
    }

    @Override
    public CompletableFuture<OperationResult> mpcProtocol(Session session, String computationId, String message) {
        return apiClient.mpcProtocol(session, computationId, message);
    }

    @Override
    public CompletableFuture<OperationResult> proxyEncryptSecret(Session session, String scope, String table, ProxyEncryptedData pre) {
        return apiClient.proxyEncryptSecret(session, scope, table, pre);
    }

    @Override
    public CompletableFuture<OperationResult> proxyReEncryptSecret(Session session, String scope, String table) {
        return apiClient.proxyReEncryptSecret(session, scope, table);
    }

    @Override
    public CompletableFuture<OperationResult> blindSignature(Session session, String blinded) {
        return apiClient.blindSignature(session, blinded);
    }

    @Override
    public boolean proxyEncrypt(Session session, String scope, String table, List<List<Object>> data, List<String> readerPublicKeys, DataLayout layout) {
        return apiClient.proxyEncrypt(session, scope, table, data, readerPublicKeys, layout);
    }

    @Override
    public boolean proxyDecrypt(Session session, List<Map<String, Object>> data, String pre, BLSKeyPair readerKeyPair, DataLayout layout) {
        return apiClient.proxyDecrypt(session, data, pre, readerKeyPair, layout);
    }

    @Override
    public CompletableFuture<OperationResult> broadcast(Session session, ConsensusMessage message) {
        return apiClient.broadcast(session, message);
    }

    @Override
    public String sign(String data) {
        return apiClient.sign(data);
    }

    @Override
    public boolean verifySignature(PublicKey publicKey, String signature, String data) {
        return apiClient.verifySignature(publicKey, signature, data);
    }

    @Override
    public boolean verifyLineageSignature(String signature, String inputsHash, String computeHash, String paramsHash, String data) {
        return apiClient.verifyLineageSignature(signature, inputsHash, computeHash, paramsHash, data);
    }

    @Override
    public boolean verifyLineageSignatureTs(String signature, String timestamp, String inputsHash, String computeHash, String paramsHash, String data) {
        return apiClient.verifyLineageSignatureTs(signature, timestamp, inputsHash, computeHash, paramsHash, data);
    }

    @Override
    public String zkDataProof(String data, byte[] challenge) {
        return apiClient.zkDataProof(data, challenge);
    }

    @Override
    public boolean verifyDataProof(String data, byte[] challenge, String transcript) {
        return apiClient.verifyDataProof(data, challenge, transcript);
    }

    @Override
    public String zkDataProof(Records data, byte[] challenge) {
        return apiClient.zkDataProof(data, challenge);
    }

    @Override
    public boolean verifyDataProof(Records data, byte[] challenge, String transcript) {
        return apiClient.verifyDataProof(data, challenge, transcript);
    }


    @Override
    public CompletableFuture<OperationResult> zkProof(Session session, String scope, String table, String gadgetType, String params, List<String> fields, Filter filter, ZKOptions options) {
        return apiClient.zkProof(session, scope, table, gadgetType, params, fields, filter, options);
    }

    @Override
    public CompletableFuture<OperationResult> zkDataProof(Session session, String gadgetType, String params, List<Object> values, ZKOptions options) {
        return apiClient.zkDataProof(session, gadgetType, params, values, options);
    }

    @Override
    public CompletableFuture<OperationResult> proofsLastHash(Session session, String scope, String table) {
        return apiClient.proofsLastHash(session, scope, table);
    }

    @Override
    public CompletableFuture<OperationResult> updateProofs(Session session, String scope, String table) {
        return apiClient.updateProofs(session, scope, table);
    }

    @Override
    public CompletableFuture<OperationResult> zkProof(Object value, String gadgetType, String params, ZKOptions options) {
        return apiClient.zkProof(value, gadgetType, params, options);
    }

    @Override
    public boolean verifyZkProof(String proof, String gadgetType, String params) {
        return apiClient.verifyZkProof(proof, gadgetType, params);
    }

    @Override
    public boolean verifyZkProof(String proof, String gadgetType, String params, String commitment, Integer nGenerators) {
        return apiClient.verifyZkProof(proof, gadgetType, params, commitment, nGenerators);
    }

    //lineage interface
    @Override
    public CompletableFuture<OperationResult> taskLineage(Session session, String taskId) {
        return apiClient.taskLineage(session, taskId);
    }

    @Override
    public CompletableFuture<OperationResult> hashCheckpoint(Session session) {
        return apiClient.hashCheckpoint(session, null);
    }

    @Override
    public CompletableFuture<OperationResult> hashCheckpoint(Session session, Boolean enable) {
        return apiClient.hashCheckpoint(session, enable);
    }

    @Override
    public CompletableFuture<OperationResult> verifyTaskLineage(Session session, Map<String, Object> lineageData) {
        return apiClient.verifyTaskLineage(session, lineageData);
    }

    @Override
    public CompletableFuture<OperationResult> taskOutputData(Session session, String taskId, OutputOptions options) {
        return apiClient.taskOutputData(session, taskId, options);
    }

    @Override
    public CompletableFuture<OperationResult> history(Session session, String scope, String table, Filter filter, HistoryOptions options) {
        return apiClient.history(session, scope, table, filter, options);
    }

    @Override
    public CompletableFuture<OperationResult> writers(Session session, String scope, String table, Filter filter) {
        return apiClient.writers(session, scope, table, filter);
    }

    @Override
    public CompletableFuture<OperationResult> tasks(Session session, String scope, String table, Filter filter) {
        return apiClient.tasks(session, scope, table, filter);
    }

    @Override
    public CompletableFuture<OperationResult> lineage(Session session, String scope, String table, Filter filter) {
        return apiClient.lineage(session, scope, table, filter);
    }


    //messaging interface
    @Override
    public CompletableFuture<OperationResult> postMessage(Session session, String targetInboxKey, String message, MessageOptions options) {
        return apiClient.postMessage(session, targetInboxKey, message, options);
    }

    @Override
    public CompletableFuture<OperationResult> pollMessages(Session session, String inboxKey, MessageOptions options) {
        return apiClient.pollMessages(session, inboxKey, options);
    }

    //feed interface
    @Override
    public CompletableFuture<OperationResult> deployOracle(Session session, String oracleType, String targetBlockchain, String source, DeployOptions options) {
        return apiClient.deployOracle(session, oracleType, targetBlockchain, source, options);
    }

    @Override
    public CompletableFuture<OperationResult> deployFeed(Session session, String image, DeployOptions options) {
        return apiClient.deployFeed(session, image, options);
    }

    @Override
    public CompletableFuture<OperationResult> startFeed(Session session, String feedId, ComputeOptions options) {
        return apiClient.startFeed(session, feedId, options);
    }

    @Override
    public CompletableFuture<OperationResult> removeFeed(Session session, String feedId) {
        return apiClient.removeFeed(session, feedId);
    }

    @Override
    public CompletableFuture<OperationResult> stopFeed(Session session, String feedId) {
        return apiClient.stopFeed(session, feedId);
    }

    //blockchain interface
    @Override
    public CompletableFuture<OperationResult> createAccount(Session session, String publicKey) {
        return apiClient.createAccount(session, publicKey);
    }

    @Override
    public CompletableFuture<OperationResult> deploy(Session session, String contractType) {
        return apiClient.deploy(session, contractType);
    }

    @Override
    public CompletableFuture<OperationResult> call(Session session, String contractAddress, String scope, String function, byte[] data) {
        return apiClient.call(session, contractAddress, scope, function, data);
    }

    @Override
    public CompletableFuture<OperationResult> balance(Session session, String accountAddress, String scope, String token) {
        return apiClient.balance(session, accountAddress, scope, token);
    }

    @Override
    public CompletableFuture<OperationResult> transfer(Session session, String accountAddress, String scope, String token, BigDecimal amount) {
        return apiClient.transfer(session, accountAddress, scope, token, amount);
    }

    @Override
    public CompletableFuture<OperationResult> updateFees(Session session, String scope, String fees) {
        return apiClient.updateFees(session, scope, fees);
    }

    @Override
    public CompletableFuture<OperationResult> contractState(Session session, String contractAddress, String scope) {
        return apiClient.contractState(session, contractAddress, scope);
    }

    @Override
    public CompletableFuture<OperationResult> broadcastBlock(Session session, String scope, String block) {
        return apiClient.broadcastBlock(session, scope, block);
    }

    @Override
    public CompletableFuture<OperationResult> broadcastChain(Session session, String scope, List<String> blocks) {
        return apiClient.broadcastChain(session, scope, blocks);
    }

    //credentials interface
    @Override
    public String getUserDID() {
        return apiClient.getUserDID();
    }

    @Override
    public String generateDID(String method) {
        return apiClient.generateDID(method);
    }

    @Override
    public CompletableFuture<OperationResult> issueCredentials(Session session, String issuer, String holder, Map<String, Object> credentials, CredentialsOptions options) {
        return apiClient.issueCredentials(session, issuer, holder, credentials, options);
    }

    @Override
    public CompletableFuture<OperationResult> verifyCredentials(Session session, Map<String, Object> credentials, CredentialsOptions options) {
        return apiClient.verifyCredentials(session, credentials, options);
    }

    @Override
    public CompletableFuture<OperationResult> createPresentation(Session session, Map<String, Object> credentials, String subject, CredentialsOptions options) {
        return apiClient.createPresentation(session, credentials, subject, options);
    }

    @Override
    public CompletableFuture<OperationResult> signPresentation(Session session, Map<String, Object> presentation, String domain, String challenge, CredentialsOptions options) {
        return apiClient.signPresentation(session, presentation, domain, challenge, options);
    }

    @Override
    public CompletableFuture<OperationResult> verifyPresentation(Session session, Map<String, Object> signedPresentation, String domain, String challenge, CredentialsOptions options) {
        return apiClient.verifyPresentation(session, signedPresentation, domain, challenge, options);
    }

    //admin interface
    @Override
    public CompletableFuture<OperationResult> peerStatus(Session session, List<String> queuedReplies) {
        return apiClient.peerStatus(session, queuedReplies);
    }

    @Override
    public CompletableFuture<OperationResult> forwardedRequest(Session session, Map<String, Object> msg) {
        return apiClient.forwardedRequest(session, msg);
    }

    @Override
    public CompletableFuture<OperationResult> getSidechainDetails(Session session) {
        return apiClient.getSidechainDetails(session);
    }


    @Override
    public CompletableFuture<OperationResult> getNodes(Session session) {
        return apiClient.getNodes(session);
    }

    @Override
    public CompletableFuture<OperationResult> getScopes(Session session) {
        return apiClient.getScopes(session);
    }

    @Override
    public CompletableFuture<OperationResult> getTables(Session session, String scope) {
        return apiClient.getTables(session, scope);
    }

    @Override
    public CompletableFuture<OperationResult> getTableDefinition(Session session, String scope, String table) {
        return apiClient.getTableDefinition(session, scope, table);
    }

    @Override
    public CompletableFuture<OperationResult> getNodeConfig(Session session, String nodePublicKey) {
        return apiClient.getNodeConfig(session, nodePublicKey);
    }

    @Override
    public CompletableFuture<OperationResult> getAccountNotifications(Session session) {
        return apiClient.getAccountNotifications(session);
    }

    @Override
    public CompletableFuture<OperationResult> updateLayout(Session session, String scope, String table, String layout) {
        return apiClient.updateLayout(session, scope, table, layout);
    }

    @Override
    public CompletableFuture<OperationResult> updateConfig(Session session, String path, Map<String, Object> values) {
        return apiClient.updateConfig(session, path, values);
    }

    @Override
    public CompletableFuture<OperationResult> grantRole(Session session, String account, Set<String> roles) {
        return apiClient.grantRole(session, account, roles);
    }

    @Override
    public CompletableFuture<OperationResult> createUserAccount(Session session, String targetOrganization, String newAccount, String publicKey, Set<String> roles, boolean isSuperAdmin) {
        return apiClient.createUserAccount(session, targetOrganization, newAccount, publicKey, roles, isSuperAdmin);
    }

    @Override
    public CompletableFuture<OperationResult> resetConfig(Session session) {
        return apiClient.resetConfig(session);
    }

    @Override
    public CompletableFuture<OperationResult> withdraw(Session session, String token, BigInteger amount) {
        return apiClient.withdraw(session, token, amount);
    }

    @Override
    public CompletableFuture<OperationResult> withdrawAuthorize(Session session, String token, String address) {
        return apiClient.withdrawAuthorize(session, token, address);
    }

    @Override
    public CompletableFuture<OperationResult> uploadApi(Session session, Map<String, Object> params) {
        return apiClient.uploadApi(session, params);
    }

    @Override
    public OperationResult tokenUpload(String apiUrl, String token, String scope, Records records, WriteOptions options) {
        return apiClient.tokenUpload(apiUrl, token, scope, records, options);
    }

    @Override
    public CompletableFuture<OperationResult> setThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        return apiClient.setThresholdSigPubKey(session, scope, table, options);
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigPubkeyRound1(Session session, String scope, String table, String uuid, String message, ThresholdSigOptions options) {
        return apiClient.thresholdSigPubkeyRound1(session, scope, table, uuid, message, options);
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigRound2(Session session, String scope, String table, String uuid, String message, byte[] scalarK, ThresholdSigOptions options) {
        return apiClient.thresholdSigRound2(session, scope, table, uuid, message, scalarK, options);
    }

    @Override
    public CompletableFuture<OperationResult> readThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        return apiClient.readThresholdSigPubKey(session, scope, table, options);
    }

    @Override
    public Map<String, Object> blindMessage(String signerPublicKey, byte[] message) {
        return apiClient.blindMessage(signerPublicKey, message);
    }

    @Override
    public String blindSign(String signerPublicKey, String signature, BigInteger factor) {
        return apiClient.blindSign(signerPublicKey, signature, factor);
    }

    @Override
    public boolean verifyBlindSignature(String signerPublicKey, byte[] message, String signature) {
        return apiClient.verifyBlindSignature(signerPublicKey, message, signature);
    }
}
