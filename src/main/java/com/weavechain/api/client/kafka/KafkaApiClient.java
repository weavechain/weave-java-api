package com.weavechain.api.client.kafka;

import com.weavechain.api.ApiContext;
import com.weavechain.api.auth.BLSKeyPair;
import com.weavechain.api.client.WeaveApiClientV1;
import com.weavechain.api.config.transport.KafkaClientConfig;
import com.weavechain.api.pre.ProxyEncryptedData;
import com.weavechain.api.session.Session;
import com.weavechain.core.consensus.ConsensusMessage;
import com.weavechain.core.constants.KafkaConstants;
import com.weavechain.core.data.filter.Filter;
import com.weavechain.core.data.Records;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.KeyExchange;
import com.weavechain.core.encrypt.KeysProvider;
import com.weavechain.core.error.AccessError;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.file.FileFormat;
import com.weavechain.core.operations.*;
import com.weavechain.core.requests.RequestType;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

import com.weavechain.core.utils.CompletableFuture;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.LongSerializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.bitcoinj.base.Base58;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

import static com.weavechain.core.constants.KafkaConstants.LOGIN_REQUEST_TOPIC;
import static com.weavechain.core.constants.KafkaConstants.SESSION_TOPIC;

@Slf4j
public class KafkaApiClient extends WeaveApiClientV1 {

    private static final int THROTTLE_MS = 10;

    private static final int MAX_LOGIN_WAIT_MS = 30_000;

    private final String clientUUID = Utils.generateUUID();
    private final KafkaClientConfig config;
    private final String ownServerPublicKey;

    private KafkaProducer<String, String> kafkaProducer;
    private final SyncRequestExecutor syncRequestExecutor;

    public KafkaApiClient(KafkaClientConfig config, ApiContext apiContext) {
        super(apiContext);
        this.config = config.copy();
        this.ownServerPublicKey = apiContext.getPublicKey();
        this.syncRequestExecutor = new SyncRequestExecutor(config.getBrokers());
    }

    @Override
    public boolean init() {
        try {
            keysInit();

            return true;
        } catch (Exception e) {
            log.error("Could not retrieve server public key", e);
            return false;
        }
    }

    private KafkaConsumer<String, String> getKafkaConsumerAndSeekToTopicBeginning(String topic) {
        Properties properties = new Properties();
        properties.setProperty(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, config.getBrokers());
        properties.setProperty(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        properties.setProperty(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());

        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(properties);
        TopicPartition tp = new TopicPartition(topic, 0);
        consumer.assign(Collections.singleton(tp));
        consumer.seek(tp, 0);
        return consumer;
    }

    private synchronized KafkaProducer<String, String> getKafkaProducer() {
        if (kafkaProducer == null) {
            Properties props = new Properties();
            props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, config.getBrokers());
            props.put(ProducerConfig.CLIENT_ID_CONFIG, config.getClientId());
            props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, LongSerializer.class.getName());
            props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
            kafkaProducer = new KafkaProducer<>(props);
        }
        return kafkaProducer;
    }

    @Override
    public CompletableFuture<OperationResult> version() {
        return asyncCall(syncRequestExecutor::syncVersion);
    }

    @Override
    public CompletableFuture<OperationResult> ping() {
        return asyncCall(syncRequestExecutor::syncPing);
    }

    @Override
    public CompletableFuture<OperationResult> publicKey() {
        return asyncCall(() -> ServerPublicKeyResolver.syncPublicKey(config.getBrokers(), ownServerPublicKey));
    }

    @Override
    public CompletableFuture<OperationResult> sigKey() {
        return sigKey(ownServerPublicKey);
    }

    public CompletableFuture<OperationResult> sigKey(String account) {
        return asyncCall(() -> ServerPublicKeyResolver.syncPublicKey(config.getBrokers(), account));
    }

    @Override
    public CompletableFuture<OperationResult> rsaKey() {
        return rsaKey(ownServerPublicKey);
    }

    public CompletableFuture<OperationResult> rsaKey(String account) {
        return asyncCall(() -> ServerPublicKeyResolver.syncPublicKey(config.getBrokers(), account));
    }

    @Override
    public CompletableFuture<OperationResult> blsKey() {
        return blsKey(ownServerPublicKey);
    }

    public CompletableFuture<OperationResult> blsKey(String account) {
        return asyncCall(() -> ServerPublicKeyResolver.syncPublicKey(config.getBrokers(), account));
    }

    private Session syncLogin(String organization, String account, String scopes, String credentials, int waitMs) {
        Map<String, String> loginMessage = new HashMap<>();
        loginMessage.put("clientUUID", clientUUID);
        loginMessage.put("organization", organization);
        loginMessage.put("account", account);
        loginMessage.put("scopes", scopes);
        loginMessage.put("credentials", credentials);

        List<String> whatIsSigned = Arrays.asList("organization", "account", "scopes", "credentials");
        String toSign = whatIsSigned.stream().map(loginMessage::get).collect(Collectors.joining("\n"));
        byte[] iv = KeysProvider.generateIV();
        String signature = signString(toSign, iv);
        loginMessage.put("x-key", getClientPublicKey());
        loginMessage.put("x-sig-key", KeysProvider.derivePublicSigKey(getApiContext().getClientPrivateKey()));
        loginMessage.put("x-rsa-key", KeysProvider.derivePublicRSAKey(getApiContext().getClientPrivateKey()));
        BLSKeyPair blsKeyPair = getBlsKeyPair();
        if (blsKeyPair != null && blsKeyPair.getPublicKey() != null) {
            loginMessage.put("x-bls-key", Base58.encode(blsKeyPair.getPublicKey()));
        }
        loginMessage.put("x-iv", Hex.toHexString(iv));
        loginMessage.put("x-sig", signature);
        addDelegateSignature(loginMessage);
        loginMessage.put(KafkaConstants.WHAT_IS_SIGNED, Utils.getGson().toJson(whatIsSigned));

        // send LOGIN
        log.info("Sent login request to server...");
        getKafkaProducer().send(new ProducerRecord<>(LOGIN_REQUEST_TOPIC, Utils.getGson().toJson(loginMessage)));

        // wait for response in SESSION queue
        long startTime = System.currentTimeMillis();
        while (!Thread.interrupted()) {
            KafkaConsumer<String, String> consumer = getKafkaConsumerAndSeekToTopicBeginning(SESSION_TOPIC);
            ConsumerRecords<String, String> cr = consumer.poll(Duration.ofMillis(THROTTLE_MS));
            for (ConsumerRecord<String, String> sessionRecord : cr.records(SESSION_TOPIC)) {
                Map<String, String> sessionDetails = Utils.getGson().<Map<String, String>>fromJson(sessionRecord.value(), Map.class);
                if (!clientUUID.equals(sessionDetails.get("clientUUID"))) {
                    continue;
                }

                // need trim because for some reason the decrypted queue name is padded with 0s
                byte[] iv2 = Hex.decode(sessionDetails.get("x-iv"));
                String topicName = decryptQueueName(sessionDetails.get("encryptedQueueName"), iv2).trim(); //TODO: review. reusing the same iv at decryption is not quite ok
                String topicAckName = topicName + "_ack";
                log.info("Got session from server, private topics are:{}, {}", topicName, topicAckName);
                syncRequestExecutor.setTopicName(topicName);
                syncRequestExecutor.setTopicAckNameAndStartConsumingLoop(topicAckName);

                consumer.close();
                return Session.parse(sessionDetails, getApiContext());
            }

            long now = System.currentTimeMillis();
            if (now - startTime > waitMs) {
                break;
            } else {
                try {
                    Thread.sleep(THROTTLE_MS);
                } catch (InterruptedException e) {
                    log.warn("Error while getting session", e);
                }
            }
        }

        return null;
    }

    private Session syncProxyLogin(String node, String organization, String account, String scopes, int waitMs) {
        Map<String, Object> loginMessage = buildProxyLoginParams(node, organization, account, scopes);

        // send LOGIN
        log.info("Sent login request to server...");
        getKafkaProducer().send(new ProducerRecord<>(LOGIN_REQUEST_TOPIC, Utils.getGson().toJson(loginMessage)));

        // wait for response in SESSION queue
        long startTime = System.currentTimeMillis();
        while (!Thread.interrupted()) {
            KafkaConsumer<String, String> consumer = getKafkaConsumerAndSeekToTopicBeginning(SESSION_TOPIC);
            ConsumerRecords<String, String> cr = consumer.poll(Duration.ofMillis(THROTTLE_MS));
            for (ConsumerRecord<String, String> sessionRecord : cr.records(SESSION_TOPIC)) {
                Map<String, String> sessionDetails = Utils.getGson().<Map<String, String>>fromJson(sessionRecord.value(), Map.class);
                if (!clientUUID.equals(sessionDetails.get("clientUUID"))) {
                    continue;
                }

                // need trim because for some reason the decrypted queue name is padded with 0s
                byte[] iv2 = Hex.decode(sessionDetails.get("x-iv"));
                String topicName = decryptQueueName(sessionDetails.get("encryptedQueueName"), iv2).trim();
                String topicAckName = topicName + "_ack";
                log.info("Got session from server, private topics are:{}, {}", topicName, topicAckName);
                syncRequestExecutor.setTopicName(topicName);
                syncRequestExecutor.setTopicAckNameAndStartConsumingLoop(topicAckName);

                consumer.close();
                return Session.parse(sessionDetails, getApiContext());
            }

            long now = System.currentTimeMillis();
            if (now - startTime > waitMs) {
                break;
            } else {
                try {
                    Thread.sleep(THROTTLE_MS);
                } catch (InterruptedException e) {
                    log.warn("Error while getting session", e);
                }
            }
        }

        return null;
    }

    private String decryptQueueName(String encryptedQueueName, byte[] iv) {
        KeyExchange keyExchange = KeysProvider.getInstance();
        SecretKey secretKey = keyExchange.sharedSecret(getApiContext().getClientPrivateKey(), getApiContext().getServerPublicKey(), null);
        byte[] secretBytes = keyExchange.decrypt(secretKey, Hex.decode(encryptedQueueName), getApiContext().getSeed(), iv);
        return new String(secretBytes);
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes) {
        return asyncCall(() -> syncLogin(organization, account, scopes, null, MAX_LOGIN_WAIT_MS));
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes, String credentials) {
        return asyncCall(() -> syncLogin(organization, account, scopes, credentials, MAX_LOGIN_WAIT_MS));
    }

    @Override
    public CompletableFuture<Session> proxyLogin(String node, String organization, String account, String scopes) {
        return asyncCall(() -> syncProxyLogin(node, organization, account, scopes, MAX_LOGIN_WAIT_MS));
    }

    @Override
    public CompletableFuture<OperationResult> logout(Session session) {
        return asyncCall(() -> syncRequestExecutor.syncLogout(session));
    }

    @Override
    public CompletableFuture<OperationResult> terms(Session session, TermsOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncTerms(session, options, this));
    }

    @Override
    public CompletableFuture<OperationResult> status(Session session) {
        return asyncCall(() -> syncRequestExecutor.syncStatus(session));
    }

    @Override
    public CompletableFuture<OperationResult> createTable(Session session, String scope, String table, CreateOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncCreateTable(session, scope, table, options));
    }

    @Override
    public CompletableFuture<OperationResult> dropTable(Session session, String scope, String table, DropOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncDropTable(session, scope, table, options));
    }

    @Override
    public CompletableFuture<OperationResult> updateLayout(Session session, String scope, String table, String layout) {
        return asyncCall(() -> syncRequestExecutor.syncUpdateLayout(session, scope, table, layout));
    }

    @Override
    public CompletableFuture<OperationResult> write(Session session, String scope, Records records, WriteOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncWrite(this, session, scope, records, options));
    }

    @Override
    public CompletableFuture<OperationResult> read(Session session, String scope, String table, Filter filter, ReadOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncRead(session, scope, table, filter, options));
    }

    @Override
    public CompletableFuture<OperationResult> count(Session session, String scope, String table, Filter filter, ReadOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncCount(session, scope, table, filter, options));
    }

    @Override
    public CompletableFuture<OperationResult> delete(Session session, String scope, String table, Filter filter, DeleteOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncDelete(session, scope, table, filter, options));
    }

    @Override
    public CompletableFuture<OperationResult> hashes(Session session, String scope, String table, Filter filter, ReadOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncHashes(session, scope, table, filter, options));
    }

    @Override
    public CompletableFuture<OperationResult> downloadTable(Session session, String scope, String table, Filter filter, FileFormat format, ReadOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncDownloadTable(session, scope, table, filter, format, options));
    }

    @Override
    public CompletableFuture<OperationResult> downloadDataset(Session session, String did, ReadOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncDownloadDataset(session, did, options));
    }

    @Override
    public CompletableFuture<OperationResult> publishDataset(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String scope, String table, Filter filter, FileFormat format, BigDecimal price, String token, Long pageorder, PublishDatasetOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncPublishDataset(session, did, name, description, license, metadata, weave, fullDescription, logo, category, scope, table, filter, format, price, token, pageorder, options));
    }

    @Override
    public CompletableFuture<OperationResult> enableProduct(Session session, String did, String productType, Boolean active) {
        return asyncCall(() -> syncRequestExecutor.syncEnableProduct(session, did, productType, active));
    }

    @Override
    public CompletableFuture<OperationResult> runTask(Session session, String did, ComputeOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncRunTask(session, did, options));
    }

    @Override
    public CompletableFuture<OperationResult> publishTask(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String task, BigDecimal price, String token, Long pageorder, PublishTaskOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncPublishTask(session, did, name, description, license, metadata, weave, fullDescription, logo, category, task, price, token, pageorder, options));
    }

    @Override
    public CompletableFuture<OperationResult> subscribe(Session session, String scope, String table, Filter filter, SubscribeOptions options, BiConsumer<String, Records> onData) {
        return asyncCall(() -> syncRequestExecutor.syncSubscribe(session, scope, table, filter, options, onData));
    }

    @Override
    public CompletableFuture<OperationResult> unsubscribe(Session session, String subscriptionId) {
        return asyncCall(() -> syncRequestExecutor.syncUnsubscribe(session, subscriptionId));
    }

    @Override
    public CompletableFuture<OperationResult> compute(Session session, String image, ComputeOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncCompute(session, image, options));
    }

    @Override
    public CompletableFuture<OperationResult> flearn(Session session, String image, FLOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncFLearn(session, image, options));
    }

    @Override
    public CompletableFuture<OperationResult> splitLearn(Session session, String image, SplitLearnOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncSplitLearn(session, image, options));
    }

    @Override
    public CompletableFuture<OperationResult> heGetInputs(Session session, List<Object> datasources, List<Object> args) {
        return asyncCall(() -> syncRequestExecutor.syncHEGetInputs(session, datasources, args));
    }

    @Override
    public CompletableFuture<OperationResult> heGetOutputs(Session session, String encoded, List<Object> args) {
        return asyncCall(() -> syncRequestExecutor.syncHEGetOutputs(session, encoded, args));
    }

    @Override
    public CompletableFuture<OperationResult> heEncode(Session session, List<Object> items) {
        return asyncCall(() -> syncRequestExecutor.syncHEEncode(session, items));
    }

    @Override
    public CompletableFuture<OperationResult> pluginCall(Session session, String plugin, String request, Map<String, Object> args, int timeoutSec) {
        return asyncCall(() -> syncRequestExecutor.syncPluginCall(session, plugin, request, args, timeoutSec));
    }

    @Override
    public CompletableFuture<OperationResult> zkProof(Session session, String scope, String table, String gadget, String params, List<String> fields, Filter filter, ZKOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncZkProof(session, scope, table, gadget, params, fields, filter, options));
    }

    @Override
    public CompletableFuture<OperationResult> zkDataProof(Session session, String gadget, String params, List<Object> values, ZKOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncZkDataProof(session, gadget, params, values, options));
    }

    @Override
    public CompletableFuture<OperationResult> proofsLastHash(Session session, String scope, String table) {
        return asyncCall(() -> syncRequestExecutor.syncProofsLastHash(session, scope, table));
    }

    @Override
    public CompletableFuture<OperationResult> updateProofs(Session session, String scope, String table) {
        return asyncCall(() -> syncRequestExecutor.syncUpdateProofs(session, scope, table));
    }

    @Override
    public CompletableFuture<OperationResult> mpc(Session session, String scope, String table, String algo, List<String> fields, Filter filter, MPCOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncMPC(session, scope, table, algo, fields, filter, options));
    }

    @Override
    public CompletableFuture<OperationResult> mpcInitProtocol(Session session, String computationId, int nodeIndex, String scope, String table, String algo, List<String> fields, Filter filter, Map<String, Integer> indexedPeers, MPCOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncMPCInitProtocol(session, computationId, nodeIndex, scope, table, algo, fields, filter, indexedPeers, options));
    }

    @Override
    public CompletableFuture<OperationResult> mpcProtocol(Session session, String computationId, String message) {
        return asyncCall(() -> syncRequestExecutor.syncMPCProtocol(session, computationId, message));
    }

    @Override
    public CompletableFuture<OperationResult> proxyEncryptSecret(Session session, String scope, String table, ProxyEncryptedData pre) {
        return asyncCall(() -> syncRequestExecutor.syncProxyEncryptSecret(session, scope, table, pre));
    }

    @Override
    public CompletableFuture<OperationResult> proxyReEncryptSecret(Session session, String scope, String table) {
        return asyncCall(() -> syncRequestExecutor.syncProxyReencryptSecret(session, scope, table));
    }

    @Override
    public CompletableFuture<OperationResult> blindSignature(Session session, String blinded) {
        return asyncCall(() -> syncRequestExecutor.syncBlindSignature(session, blinded));
    }

    @Override
    public CompletableFuture<OperationResult> storageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncStorageProof(session, scope, table, filter, challenge, options));
    }

    @Override
    public CompletableFuture<OperationResult> zkStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncZkStorageProof(session, scope, table, filter, challenge, options));
    }

    @Override
    public CompletableFuture<OperationResult> merkleTree(Session session, String scope, String table, Filter filter, String salt, ReadOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncMerkleTree(session, scope, table, filter, salt, options));
    }

    @Override
    public CompletableFuture<OperationResult> merkleProof(Session session, String scope, String table, String hash) {
        return asyncCall(() -> syncRequestExecutor.syncMerkleProof(session, scope, table, hash));
    }

    @Override
    public CompletableFuture<OperationResult> zkMerkleTree(Session session, String scope, String table, Filter filter, String salt, Integer rounds, Integer seed, ZKOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncZkMerkleTree(session, scope, table, filter, salt, rounds, seed, options));
    }

    @Override
    public CompletableFuture<OperationResult> rootHash(Session session, String scope, String table) {
        return asyncCall(() -> syncRequestExecutor.syncRoothash(session, scope, table));
    }

    @Override
    public CompletableFuture<OperationResult> verifyDataSignature(Session session, String signer, String signature, String data) {
        return asyncCall(() -> syncRequestExecutor.syncVerifyDataSignature(session, signer, signature, data));
    }

    @Override
    public CompletableFuture<OperationResult> taskLineage(Session session, String taskId) {
        return asyncCall(() -> syncRequestExecutor.syncTaskLineage(session, taskId));
    }

    @Override
    public CompletableFuture<OperationResult> hashCheckpoint(Session session) {
        return hashCheckpoint(session, null);
    }

    @Override
    public CompletableFuture<OperationResult> hashCheckpoint(Session session, Boolean enable) {
        return asyncCall(() -> syncRequestExecutor.syncHashCheckpoint(session, enable));
    }

    @Override
    public CompletableFuture<OperationResult> verifyTaskLineage(Session session, Map<String, Object> metadata) {
        return asyncCall(() -> syncRequestExecutor.syncVerifyTaskLineage(session, metadata));
    }

    @Override
    public CompletableFuture<OperationResult> taskOutputData(Session session, String taskId, OutputOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncTaskOutputData(session, taskId, options));
    }

    @Override
    public CompletableFuture<OperationResult> history(Session session, String scope, String table, Filter filter, HistoryOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncHistory(session, scope, table, filter, options));
    }

    @Override
    public CompletableFuture<OperationResult> writers(Session session, String scope, String table, Filter filter) {
        return asyncCall(() -> syncRequestExecutor.syncWriters(session, scope, table, filter));
    }

    @Override
    public CompletableFuture<OperationResult> tasks(Session session, String scope, String table, Filter filter) {
        return asyncCall(() -> syncRequestExecutor.syncTasks(session, scope, table, filter));
    }

    @Override
    public CompletableFuture<OperationResult> lineage(Session session, String scope, String table, Filter filter) {
        return asyncCall(() -> syncRequestExecutor.syncLineage(session, scope, table, filter));
    }

    @Override
    public CompletableFuture<OperationResult> broadcast(Session session, ConsensusMessage message) {
        return asyncCall(() -> syncRequestExecutor.syncBroadcast(session, message));
    }

    @Override
    public CompletableFuture<OperationResult> createAccount(Session session, String publicKey) {
        return asyncCall(() -> syncRequestExecutor.syncCreateUserAccount(session, publicKey, ChainOptions.DEFAULT));
    }

    @Override
    public CompletableFuture<OperationResult> deploy(Session session, String contractType) {
        return asyncCall(() -> syncRequestExecutor.syncDeploy(session, contractType, ChainOptions.DEFAULT));
    }

    @Override
    public CompletableFuture<OperationResult> call(Session session, String contractAddress, String scope, String function, byte[] data) {
        return asyncCall(() -> syncRequestExecutor.syncCall(session, contractAddress, scope, function, data, ChainOptions.DEFAULT));
    }

    @Override
    public CompletableFuture<OperationResult> balance(Session session, String accountAddress, String scope, String token) {
        return asyncCall(() -> syncRequestExecutor.syncBalance(session, accountAddress, scope, token));
    }

    @Override
    public CompletableFuture<OperationResult> transfer(Session session, String accountAddress, String scope, String token, BigDecimal amount) {
        return asyncCall(() -> syncRequestExecutor.syncTransfer(session, accountAddress, scope, token, amount));
    }

    @Override
    public CompletableFuture<OperationResult> updateFees(Session session, String scope, String fees) {
        return asyncCall(() -> syncRequestExecutor.syncUpdateFees(session, scope, fees));
    }

    @Override
    public CompletableFuture<OperationResult> contractState(Session session, String contractAddress, String scope) {
        return asyncCall(() -> syncRequestExecutor.syncContractState(session, contractAddress, scope, ChainOptions.DEFAULT));
    }

    @Override
    public CompletableFuture<OperationResult> broadcastBlock(Session session, String scope, String block) {
        return asyncCall(() -> syncRequestExecutor.syncBroadcastBlock(session, scope, block, ChainOptions.DEFAULT));
    }

    @Override
    public CompletableFuture<OperationResult> broadcastChain(Session session, String scope, List<String> blocks) {
        return asyncCall(() -> syncRequestExecutor.syncBroadcastChain(session, scope, blocks, ChainOptions.DEFAULT));
    }

    @Override
    public CompletableFuture<OperationResult> forwardedRequest(Session session, Map<String, Object> msg) {
        return asyncCall(() -> syncRequestExecutor.syncForwardedRequest(session, msg));
    }

    @Override
    public CompletableFuture<OperationResult> getSidechainDetails(Session session) {
        return asyncCall(() -> syncRequestExecutor.syncGet(session, RequestType.get_sidechain_details));
    }

    @Override
    public CompletableFuture<OperationResult> getNodes(Session session) {
        return asyncCall(() -> syncRequestExecutor.syncGet(session, RequestType.get_nodes));
    }

    @Override
    public CompletableFuture<OperationResult> getScopes(Session session) {
        return asyncCall(() -> syncRequestExecutor.syncGet(session, RequestType.get_scopes));
    }

    @Override
    public CompletableFuture<OperationResult> getTables(Session session, String scope) {
        return asyncCall(() -> syncRequestExecutor.syncGet(session, RequestType.get_tables));
    }

    @Override
    public CompletableFuture<OperationResult> getTableDefinition(Session session, String scope, String table) {
        return null;
    }

    @Override
    public CompletableFuture<OperationResult> getNodeConfig(Session session, String nodePublicKey) {
        return asyncCall(() -> syncRequestExecutor.syncGet(session, RequestType.get_node_config));
    }

    @Override
    public CompletableFuture<OperationResult> getAccountNotifications(Session session) {
        return asyncCall(() -> syncRequestExecutor.syncGet(session, RequestType.get_account_notifications));
    }

    @Override
    public CompletableFuture<OperationResult> updateConfig(Session session, String path, Map<String, Object> values) {
        return asyncCall(() -> syncRequestExecutor.syncUpdateConfig(session, path, values));
    }

    @Override
    public CompletableFuture<OperationResult> grantRole(Session session, String account, Set<String> roles) {
        return asyncCall(() -> syncRequestExecutor.syncGrantRole(session, account, roles));
    }

    @Override
    public CompletableFuture<OperationResult> createUserAccount(Session session, String targetOrganization, String newAccount, String publicKey, Set<String> roles, boolean isSuperAdmin) {
        return asyncCall(() -> syncRequestExecutor.syncCreateUserAccount(session, targetOrganization, newAccount, publicKey, roles, isSuperAdmin));
    }

    @Override
    public CompletableFuture<OperationResult> resetConfig(Session session) {
        return asyncCall(() -> syncRequestExecutor.syncResetConfig(session));
    }

    @Override
    public CompletableFuture<OperationResult> withdraw(Session session, String token, BigInteger amount) {
        return asyncCall(() -> syncRequestExecutor.syncWithdraw(session, amount));
    }

    @Override
    public CompletableFuture<OperationResult> withdrawAuthorize(Session session, String token, String address) {
        try {
            String toSign = token + "\n" + address;
            String signature = KeysProvider.createAccountSignature(getApiContext().getSigPrivateKey(), toSign.getBytes(StandardCharsets.UTF_8));

            return asyncCall(() -> syncRequestExecutor.syncWithdrawAuthorize(session, token, address, signature));
        } catch (Exception e) {
            CompletableFuture<OperationResult> result = new CompletableFuture<>();
            result.complete(new AccessError(null, "Failed withdraw authorize "+ e.toString()));
            return result;
        }
    }

    public CompletableFuture<OperationResult> uploadApi(Session session, Map<String, Object> params) {
        return asyncCall(() -> syncRequestExecutor.syncUploadApi(session, params));
    }

    public CompletableFuture<OperationResult> setThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncSetThresholdSigPubKey(session, scope, table, options));
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigPubkeyRound1(Session session, String scope, String table, String uuid, String message, ThresholdSigOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncThresholdSigPubkeyRound1(session, scope, table, message, options));
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigRound2(Session session, String scope, String table, String uuid, String message, byte[] scalarK, ThresholdSigOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncThresholdSigRound2(session, scope, table, uuid, message, scalarK, options));
    }

    @Override
    public CompletableFuture<OperationResult> readThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncReadThresholdSigPubKey(session, scope, table, options));
    }

    @Override
    public CompletableFuture<OperationResult> deployOracle(Session session, String oracleType, String targetBlockchain, String source, DeployOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncDeployOracle(session, oracleType, targetBlockchain, source, options));
    }

    @Override
    public CompletableFuture<OperationResult> postMessage(Session session, String targetInboxKey, String message, MessageOptions options) {
        return asyncCall(() -> syncRequestExecutor.postMessage(session, targetInboxKey, message, options));
    }

    @Override
    public CompletableFuture<OperationResult> pollMessages(Session session, String inboxKey, MessageOptions options) {
        return asyncCall(() -> syncRequestExecutor.pollMessages(session, inboxKey, options));
    }

    @Override
    public CompletableFuture<OperationResult> deployFeed(Session session, String image, DeployOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncDeployFeed(session, image, options));
    }

    @Override
    public CompletableFuture<OperationResult> startFeed(Session session, String feedId, ComputeOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncStartFeed(session, feedId, options));
    }

    @Override
    public CompletableFuture<OperationResult> removeFeed(Session session, String feedId) {
        return asyncCall(() -> syncRequestExecutor.syncRemoveFeed(session, feedId));
    }

    @Override
    public CompletableFuture<OperationResult> stopFeed(Session session, String feedId) {
        return asyncCall(() -> syncRequestExecutor.syncStopFeed(session, feedId));
    }


    @Override
    public CompletableFuture<OperationResult> issueCredentials(Session session, String issuer, String holder, Map<String, Object> credentials, CredentialsOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncIssueCredentials(session, issuer, holder, credentials, options));
    }

    @Override
    public CompletableFuture<OperationResult> verifyCredentials(Session session, Map<String, Object> credentials, CredentialsOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncVerifyCredentials(session, credentials, options));
    }

    @Override
    public CompletableFuture<OperationResult> createPresentation(Session session, Map<String, Object> credentials, String subject, CredentialsOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncCreatePresentation(session, credentials, subject, options));
    }

    @Override
    public CompletableFuture<OperationResult> signPresentation(Session session, Map<String, Object> presentation, String domain, String challenge, CredentialsOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncSignPresentation(session, presentation, domain, challenge, options));
    }

    @Override
    public CompletableFuture<OperationResult> verifyPresentation(Session session, Map<String, Object> signedPresentation, String domain, String challenge, CredentialsOptions options) {
        return asyncCall(() -> syncRequestExecutor.syncVerifyPresentation(session, signedPresentation, domain, challenge, options));
    }

    @Override
    public CompletableFuture<OperationResult> peerStatus(Session session, List<String> queuedReplies) {
        return asyncCall(() -> syncRequestExecutor.syncPeerStatus(session, queuedReplies));
    }
}
