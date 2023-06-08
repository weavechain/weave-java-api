package com.weavechain.api.client.kafka;

import com.weavechain.api.client.WeaveApiClientV1;
import com.weavechain.api.pre.ProxyEncryptedData;
import com.weavechain.api.session.Session;
import com.weavechain.core.batching.BatchData;
import com.weavechain.core.batching.BatchHelper;
import com.weavechain.core.batching.RecordBatchLocation;
import com.weavechain.core.consensus.ConsensusMessage;
import com.weavechain.core.constants.KafkaConstants;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.filter.Filter;
import com.weavechain.core.data.Records;
import com.weavechain.core.encoding.ContentEncoder;
import com.weavechain.core.encoding.Encoding;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.Hash;
import com.weavechain.core.error.*;
import com.weavechain.core.file.FileFormat;
import com.weavechain.core.operations.*;
import com.weavechain.core.requests.RequestType;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.kafka.clients.consumer.ConsumerConfig;
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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

/**
 * Synchronously executes requests on behalf of a {@link KafkaApiClient}
 * Each request is executed based on the following pattern:
 * - create new message using "newMessage()"
 * - fill message with specific fields
 * - return sendRecordToTopicAndGetResponse(): this sends request on "topicName", waits for response on "topicAckName"
 */
@Slf4j
public class SyncRequestExecutor {

    //TODO: unify requests calls across connectors

    /**
     * name of topic where requests are sent
     */
    @Setter
    private String topicName;
    /**
     * name of topic where responses are read from
     */
    private String topicAckName;
    @Setter
    private String brokers;
    private KafkaProducer<String, String> kafkaProducer;
    private final AtomicInteger requestId = new AtomicInteger(0);
    private final Map<Integer, OperationResult> responsesFromServer = new ConcurrentHashMap<>();

    private final BatchHelper batchHelper = new BatchHelper();
    private final ContentEncoder contentEncoder = Encoding.getDefaultContentEncoder();

    private final Object responseLock = new Object();

    public SyncRequestExecutor(String brokers) {
        this.brokers = brokers;
    }

    void setTopicAckNameAndStartConsumingLoop(String topicAckName) {
        this.topicAckName = topicAckName;
        Executors.newSingleThreadExecutor().submit(this::responseConsumingLoop);
    }

    /**
     * Reads incoming responses and puts them in 'responsesFromServer'
     */
    private void responseConsumingLoop() {
        KafkaConsumer<String, String> privateTopicAckConsumer = getKafkaConsumerAndSeekToTopicBeginning(topicAckName);
        while (true) {
            try {
                ConsumerRecords<String, String> records = privateTopicAckConsumer.poll(Duration.ofMillis(100));
                records.records(topicAckName).forEach(record -> {
                    Map<String, Object> map = Utils.getGson().<Map<String, Object>>fromJson(record.value(), Map.class);
                    int requestId = Integer.parseInt((String) map.get("requestId"));
                    OperationResult result = OperationResultSerializer.from(map.get("result"));
                    responsesFromServer.put(requestId, result);
                    synchronized (responseLock) {
                        responseLock.notifyAll();
                    }
                });
            } catch (Exception e) {
                log.warn("Exception in private topic consumer loop", e);
            }
        }
    }

    private KafkaConsumer<String, String> getKafkaConsumerAndSeekToTopicBeginning(String topic) {
        Properties properties = new Properties();
        properties.setProperty(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, brokers);
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
            props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, brokers);
            props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, LongSerializer.class.getName());
            props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
            kafkaProducer = new KafkaProducer<>(props);
        }
        return kafkaProducer;
    }

    private Map<String, Object> newMessage() {
        Map<String, Object> newMessage = new HashMap<>();
        int id = requestId.incrementAndGet();
        newMessage.put("requestId", Integer.toString(id));
        return newMessage;
    }

    private OperationResult sendRecordToTopicAndGetResponse(String topicName, Map<String, Object> message) {
        try {
            getKafkaProducer().send(new ProducerRecord<>(topicName, Utils.getGson().toJson(message)));

            Integer messageId = Integer.parseInt(message.get("requestId").toString());
            while (!responsesFromServer.containsKey(messageId)) {
                synchronized (responseLock) {
                    responseLock.wait(100);
                }
            }
            return responsesFromServer.remove(messageId);
        } catch (Exception e) {
            log.warn("Exception while communicating with server", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncVersion() {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.version.name());

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed syncVersion", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncPing() {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.ping.name());

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed ping", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncLogout(Session session) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.logout.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed logout", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncTerms(Session session, TermsOptions options, WeaveApiClientV1 client) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.terms.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            String termsOptions = Utils.getGson().toJson(options);
            message.put("options", termsOptions);
            message.put("signature", client.sign(termsOptions));
            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed terms", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncStatus(Session session) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.status.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());

            return sendAuthenticated(message, session, Arrays.asList("organization", "account"));
        } catch (Exception e) {
            log.error("Failed status", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncCreateTable(Session session, String scope, String table, CreateOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.create.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }
            message.put("x-api-key", session.getApiKey());

            String nonce = Long.toString(session.getNonce().incrementAndGet());
            message.put("x-nonce", nonce);

            List<String> whatIsSigned = Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table");
            String toSign = whatIsSigned.stream().map(message::get).map(Object::toString).collect(Collectors.joining("\n"));
            String signature = Hash.signRequestB64(session.getSecret(), toSign);
            message.put(KafkaConstants.WHAT_IS_SIGNED, Utils.getGson().toJson(whatIsSigned));
            message.put("x-sig", signature);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed create", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncDropTable(Session session, String scope, String table, DropOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.drop.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("organization", "account", "scope", "table"));
        } catch (Exception e) {
            log.error("Failed drop", e);
            return new AccessError(null, e.toString());
        }
    }

    private OperationResult sendAuthenticated(Map<String, Object> message, Session session, List<String> whatIsSigned) {
        message.put("x-api-key", session.getApiKey());

        String nonce = Long.toString(session.getNonce().incrementAndGet());
        message.put("x-nonce", nonce);

        message.put(KafkaConstants.WHAT_IS_SIGNED, Utils.getGson().toJson(whatIsSigned));
        String toSign = whatIsSigned.stream().map(message::get).map(Object::toString).collect(Collectors.joining("\n"));
        String signature = Hash.signRequestB64(session.getSecret(), toSign);
        message.put("x-sig", signature);

        return sendRecordToTopicAndGetResponse(topicName, message);
    }

    OperationResult syncUpdateLayout(Session session, String scope, String table, String layout) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.update_layout.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("layout", layout);

            return sendAuthenticated(message, session, Arrays.asList("organization", "account", "scope", "table"));
        } catch (Exception e) {
            log.error("Failed drop", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncWrite(KafkaApiClient apiClient, Session session, String scope, Records records, WriteOptions options) {
        if (options.isAllowLocalBatching()) {
            try {
                RecordBatchLocation location = new RecordBatchLocation(session.getAccount(), session.getOrganization(), scope, records.getTable(), options);

                final BatchData currentBatch = batchHelper.getBatch(location, options.getWriteTimeoutSec() + options.getBatchingOptions().getWaitTimeMs());
                currentBatch.addRecord(records);

                batchHelper.checkBatch(currentBatch, options.getBatchingOptions(), () -> doBatchWrite(apiClient, session, currentBatch, options));

                //TODO: 2 stages, first a succes for adding to the batch then the real result.
                // To add tests that sync and async writes work as expected, a sync write from client with sync signing should provide both guarantees when done
                return new Pending(
                        new OperationScope(ApiOperationType.WRITE, session.getAccount(), session.getOrganization(), scope, records.getTable()),
                        null
                );
            } catch (Exception e) {
                log.error("Failed write", e);
                return new AccessError(null, e.toString());
            }
        } else {
            return doWrite(apiClient, session, scope, records, options);
        }
    }

    public OperationResult doBatchWrite(KafkaApiClient apiClient, Session session, BatchData batch, WriteOptions options) {
        try {
            if (batch.getDispatched().compareAndSet(false, true)) {
                Records records = new Records(batch.getLocation().getTable(), new ArrayList<>(batch.getItems().get(0).getItems()), null, null);
                for (int i = 1; i < batch.getItems().size(); i++) {
                    records.getItems().addAll(batch.getItems().get(i).getItems());
                }
                return doWrite(apiClient, session, batch.getLocation().getScope(), records, batch.getLocation().getWriteOptions());
            } else {
                return new Success(
                        new OperationScope(ApiOperationType.WRITE, session.getAccount(), session.getOrganization(), batch.getLocation().getScope(), batch.getLocation().getTable()),
                        null
                );
            }
        } catch (Exception e) {
            log.error("Failed write", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult doWrite(KafkaApiClient apiClient, Session session, String scope, Records records, WriteOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.write.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            apiClient.addIntegritySignatureIfConfigured(records, session, scope, message);
            DataLayout layout = DataLayout.DEFAULT;
            message.put("records", contentEncoder.encode(records, layout));
            if (options != null) {
                message.put("options", Utils.getWriteOptionsJsonAdapter().toJson(options));
            }
            if (contentEncoder != Encoding.getDefaultContentEncoder()) {
                message.put("enc", contentEncoder.getType());
            }
            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "records"));
        } catch (Exception e) {
            log.error("Failed write", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncRead(Session session, String scope, String table, Filter filter, ReadOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.read.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed read", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncCount(Session session, String scope, String table, Filter filter, ReadOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.count.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed count", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncDelete(Session session, String scope, String table, Filter filter, DeleteOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.delete.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed delete", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncHashes(Session session, String scope, String table, Filter filter, ReadOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.hashes.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed reading hashes", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncDownloadTable(Session session, String scope, String table, Filter filter, FileFormat format, ReadOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.download_table.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("format", format.name());
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed download", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncDownloadDataset(Session session, String did, ReadOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.download_dataset.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("did", did);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "did"));
        } catch (Exception e) {
            log.error("Failed download", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncPublishDataset(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String scope, String table, Filter filter, FileFormat format, BigDecimal price, String token, Long pageorder, PublishDatasetOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.publish_dataset.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("did", did);
            message.put("name", name);
            message.put("description", description);
            message.put("license", license);
            message.put("metadata", metadata);
            message.put("weave", weave);
            message.put("full_description", fullDescription);
            message.put("logo", logo);
            message.put("category", category);
            message.put("scope", scope);
            message.put("table", table);
            message.put("format", format.name());
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            message.put("price", price);
            message.put("token", token);
            message.put("pageorder", pageorder);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed publish", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncEnableProduct(Session session, String did, String productType, Boolean active) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.enable_product.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("did", did);
            message.put("productType", productType);
            message.put("active", active);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "did"));
        } catch (Exception e) {
            log.error("Failed enable product", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncRunTask(Session session, String did, ComputeOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.run_task.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("did", did);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "did"));
        } catch (Exception e) {
            log.error("Failed download", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncPublishTask(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String task, BigDecimal price, String token, Long pageorder, PublishTaskOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.publish_task.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("did", did);
            message.put("name", name);
            message.put("description", description);
            message.put("license", license);
            message.put("metadata", metadata);
            message.put("weave", weave);
            message.put("full_description", fullDescription);
            message.put("logo", logo);
            message.put("category", category);
            message.put("task", task);
            message.put("price", price);
            message.put("token", token);
            message.put("pageorder", pageorder);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "task", "options"));
        } catch (Exception e) {
            log.error("Failed publish", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncSubscribe(Session session, String scope, String table, Filter filter, SubscribeOptions options, BiConsumer<String, Records> onData) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.subscribe.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed subscribe", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncUnsubscribe(Session session, String subscriptionId) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.unsubscribe.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("subscriptionId", subscriptionId);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed unsubscribe", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncCompute(Session session, String image, ComputeOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.compute.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("image", image);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncFLearn(Session session, String image, FLOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.f_learn.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("image", image);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed federated learning", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncSplitLearn(Session session, String image, SplitLearnOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.split_learn.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("image", image);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed split learning", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncHEGetInputs(Session session, List<Object> datasources, List<Object> args) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.compute.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("datasources", Utils.getGson().toJson(datasources));
            if (args != null) {
                message.put("args", Utils.getGson().toJson(args));
            }

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed HE Get inputs", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncHEGetOutputs(Session session, String encoded, List<Object> args) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.compute.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("encoded", encoded);
            if (args != null) {
                message.put("args", Utils.getGson().toJson(args));
            }

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed HE Get Outputs", e);
            return new AccessError(null, e.toString());
        }
    }


    public OperationResult syncHEEncode(Session session, List<Object> items) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.he_encode.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("items", Utils.getGson().toJson(items));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed HE encode", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncPluginCall(Session session, String plugin, String request, Map<String, Object> args, int timeoutSec) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.plugin_call.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("plugin", plugin);
            message.put("request", request);
            message.put("args", args);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed plugin call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncZkProof(Session session, String scope, String table, String gadget, String params, List<String> fields, Filter filter, ZKOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.zk_proof.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("gadget", gadget);
            message.put("params", params);
            message.put("fields", Utils.getGson().toJson(fields));
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "algo", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed generating proof", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncZkDataProof(Session session, String gadget, String params, List<Object> values, ZKOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.zk_data_proof.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("gadget", gadget);
            message.put("params", params);
            message.put("values", Utils.getGson().toJson(values));
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "gadget", "params", "values"));
        } catch (Exception e) {
            log.error("Failed generating proof", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncProofsLastHash(Session session, String scope, String table) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.proofs_last_hash.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table"));
        } catch (Exception e) {
            log.error("Failed generating proof", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncUpdateProofs(Session session, String scope, String table) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.update_proofs.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table" ));
        } catch (Exception e) {
            log.error("Failed generating proof", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncMPC(Session session, String scope, String table, String algo, List<String> fields, Filter filter, MPCOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.mpc.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("algo", algo);
            message.put("fields", Utils.getGson().toJson(fields));
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "algo", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed MPC", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncMPCInitProtocol(Session session, String computationId, int nodeIndex, String scope, String table, String algo, List<String> fields, Filter filter, Map<String, Integer> indexedPeers, MPCOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.mpc_init.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("computationId", computationId);
            message.put("nodeIndex", nodeIndex);
            message.put("scope", scope);
            message.put("table", table);
            message.put("algo", algo);
            message.put("indexedPeers", Utils.getGson().toJson(indexedPeers));
            message.put("fields", Utils.getGson().toJson(fields));
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "algo", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed MPC protocol init", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncMPCProtocol(Session session, String computationId, String msg) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.mpc_proto.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("computationId", computationId);
            message.put("message", msg);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "computationId", "msg"));
        } catch (Exception e) {
            log.error("Failed MPC protocol call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncProxyEncryptSecret(Session session, String scope, String table, ProxyEncryptedData pre) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.proxy_encrypt.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("pre", pre.toJson());

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "msg"));
        } catch (Exception e) {
            log.error("Failed proxy encrypt call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncProxyReencryptSecret(Session session, String scope, String table) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.proxy_reencrypt.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table"));
        } catch (Exception e) {
            log.error("Failed proxy reencrypt call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncBlindSignature(Session session, String blinded) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.blind_signature.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("blinded", blinded);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "blinded"));
        } catch (Exception e) {
            log.error("Failed blind signature call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.storage_proof.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("challenge", challenge);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "filter", "challenge", "options"));
        } catch (Exception e) {
            log.error("Failed storage proof", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncZkStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.zk_storage_proof.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("challenge", challenge);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "filter", "challenge", "options"));
        } catch (Exception e) {
            log.error("Failed storage proof", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncMerkleTree(Session session, String scope, String table, Filter filter, String salt, ReadOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.merkle_tree.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("salt", salt);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "salt", "filter", "options"));
        } catch (Exception e) {
            log.error("Failed merkle tree call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncMerkleProof(Session session, String scope, String table, String hash) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.merkle_proof.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("hash", hash);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "hash"));
        } catch (Exception e) {
            log.error("Failed merkle proof call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncZkMerkleTree(Session session, String scope, String table, Filter filter, String salt, Integer rounds, Integer seed, ZKOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.zk_merkle_tree.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("salt", salt);
            message.put("rounds", rounds);
            message.put("seed", seed);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope", "table", "rounds", "seed", "options"));
        } catch (Exception e) {
            log.error("Failed zk merkle tree call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncRoothash(Session session, String scope, String table) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.root_hash.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope"));
        } catch (Exception e) {
            log.error("Failed root hash call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncVerifyDataSignature(Session session, String signer, String signature, String data) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.verify_data_signature.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("signer", signer);
            message.put("signature", signature);
            message.put("data", data);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "scope"));
        } catch (Exception e) {
            log.error("Failed verify data signature call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncTaskLineage(Session session, String taskId) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.task_lineage.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("taskId", taskId);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account", "taskId"));
        } catch (Exception e) {
            log.error("Failed task lineage call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncHashCheckpoint(Session session, Boolean enable) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.hash_checkpoint.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("enable", enable);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account"));
        } catch (Exception e) {
            log.error("Failed hash lineage call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncVerifyTaskLineage(Session session, Map<String, Object> metadata) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.hash_checkpoint.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("metadata", metadata);

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account"));
        } catch (Exception e) {
            log.error("Failed verify task lineage call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncTaskOutputData(Session session, String taskId, OutputOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.task_output_data.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("taskId", taskId);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account"));
        } catch (Exception e) {
            log.error("Failed hash lineage call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncHistory(Session session, String scope, String table, Filter filter, HistoryOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.history.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account"));
        } catch (Exception e) {
            log.error("Failed hash lineage call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncWriters(Session session, String scope, String table, Filter filter) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.writers.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account"));
        } catch (Exception e) {
            log.error("Failed writers call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncTasks(Session session, String scope, String table, Filter filter) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.tasks.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account"));
        } catch (Exception e) {
            log.error("Failed writer-tasks call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncLineage(Session session, String scope, String table, Filter filter) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.lineage.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (filter != null) {
                message.put("filter", Utils.getGson().toJson(filter));
            }

            return sendAuthenticated(message, session, Arrays.asList("type", "x-api-key", "x-nonce", "organization", "account"));
        } catch (Exception e) {
            log.error("Failed lineage call", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncBroadcast(Session session, ConsensusMessage consensusMessage) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.broadcast.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", consensusMessage.getScope());
            message.put("table", consensusMessage.getTable());

            message.put("x-api-key", session.getApiKey());

            String nonce = Long.toString(session.getNonce().incrementAndGet());
            message.put("x-nonce", nonce);

            List<String> whatIsSigned = Arrays.asList("organization", "account", "scope", "table");
            message.put(KafkaConstants.WHAT_IS_SIGNED, Utils.getGson().toJson(whatIsSigned));
            String toSign = whatIsSigned.stream().map(message::get).map(Object::toString).collect(Collectors.joining("\n"));
            String signature = Hash.signRequestB64(session.getSecret(), toSign);
            message.put("x-sig", signature);

            consensusMessage.getData().put("organization", session.getOrganization());
            consensusMessage.getData().put("account", session.getAccount());
            consensusMessage.getData().put("scope", consensusMessage.getScope());
            consensusMessage.getData().put("table", consensusMessage.getTable());
            consensusMessage.getData().put("type", consensusMessage.getType());
            consensusMessage.getData().put("seqNum", consensusMessage.getSeqNum());
            consensusMessage.getData().put("action", consensusMessage.getAction());
            message.put("data", Utils.getMapJsonAdapter().toJson(consensusMessage.getData()));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed read", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncCreateUserAccount(Session session, String publicKey, ChainOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.create_account.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("publicKey", publicKey);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed create account", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncDeploy(Session session, String contractType, ChainOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.deploy.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("contractType", contractType);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed deploy", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncCall(Session session, String contractAddress, String scope, String function, byte[] data, ChainOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.call.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("contractAddress", contractAddress);
            message.put("function", function);
            message.put("data", Base64.encodeBase64String(data));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed call", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncBalance(Session session, String accountAddress, String scope, String token) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.balance.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("accountAddress", accountAddress);
            message.put("scope", scope);
            message.put("token", token);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed balance", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncTransfer(Session session, String accountAddress, String scope, String token, BigDecimal amount) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.balance.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("accountAddress", accountAddress);
            message.put("scope", scope);
            message.put("token", token);
            message.put("amount", amount);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed balance", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncUpdateFees(Session session, String scope, String fees) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.update_fees.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("fees", fees);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed update fees", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncContractState(Session session, String contractAddress, String scope, ChainOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.contract_state.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("contractAddress", contractAddress);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed retrieving contract state", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncBroadcastBlock(Session session, String scope, String block, ChainOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.broadcast_block.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("block", block);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed block broadcast", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncBroadcastChain(Session session, String scope, List<String> blocks, ChainOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.broadcast_chain.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("blocks", Utils.getGson().toJson(blocks));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed chain broadcast", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncForwardedRequest(Session session, Map<String, Object> msg) {
        try {
            Map<String, Object> message = newMessage();
            for (Map.Entry<String, Object> it : msg.entrySet()) {
                message.put(it.getKey(), ConvertUtils.convertToString(it.getValue()));
            }
            message.put("type", RequestType.forwarded_request.name());

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed forwarded request", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncGet(Session session, RequestType requestType) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", requestType.name());
            message.put("account", session.getAccount());

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed " + requestType.name(), e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncUpdateConfig(Session session, String path, Map<String, Object> values) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.update_config.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("path", path);
            message.put("values", Utils.getGson().toJson(values));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed update config", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncGrantRole(Session session, String account, Set<String> roles) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.grant_role.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("targetAccount", account);
            message.put("roles", Utils.getGson().toJson(roles));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed grant role", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncCreateUserAccount(Session session, String targetOrganization, String newAccount, String publicKey, Set<String> roles, boolean isSuperAdmin) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.create_user_account.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("targetOrganization", targetOrganization);
            message.put("targetAccount", newAccount);
            message.put("publicKey", publicKey);
            message.put("roles", String.join(" ", roles));
            message.put("isSuperAdmin", isSuperAdmin ? 1 : 0);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed update config", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncWithdraw(Session session, BigInteger amount) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.withdraw.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("amount", amount);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed withdraw", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncWithdrawAuthorize(Session session, String token, String address, String signature) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.withdraw_auth.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("address", address);
            message.put("signature", signature);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed withdraw authorize", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncUploadApi(Session session, Map<String, Object> params) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.upload_api.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            if (params != null) {
                message.put("params", Utils.getGson().toJson(params));
            }

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed retrieving upload API token", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncSetThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.set_threshold_sig_pub_key.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed set threshold sig public key", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncThresholdSigPubkeyRound1(Session session, String scope, String table, String hash, ThresholdSigOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.threshold_sig_pubkey_round_1.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("hash", hash);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed threshold sig round 1", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncThresholdSigRound2(Session session, String scope, String table, String uuid, String hash, byte[] scalarK, ThresholdSigOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.threshold_sig_round_2.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            message.put("uuid", uuid);
            message.put("hash", hash);
            message.put("scalarK", Base58.encode(scalarK));
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed threshold sig round 2", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncReadThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.read_threshold_sig_pub_key.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("scope", scope);
            message.put("table", table);
            if (options != null) {
                message.put("options", Utils.getGson().toJson(options));
            }

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed read threshold sig public key", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncDeployOracle(Session session, String oracleType, String targetBlockchain, String source, DeployOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.deploy_oracle.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("oracleType", oracleType);
            message.put("targetBlockchain", targetBlockchain);
            message.put("source", source);
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed deploy oracle", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult postMessage(Session session, String targetInboxKey, String msg, MessageOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.post_message.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("targetInboxKey", targetInboxKey);
            message.put("msg", msg);
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed deploy oracle", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult pollMessages(Session session, String inboxKey, MessageOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.poll_messages.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("inboxKey", inboxKey);
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed deploy oracle", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncDeployFeed(Session session, String image, DeployOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.deploy_feed.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("image", image);
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed deploy feed", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncStartFeed(Session session, String feedId, ComputeOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.start_feed.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("feedId", feedId);
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed start feed", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncRemoveFeed(Session session, String feedId) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.remove_feed.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("feedId", feedId);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed remove feed", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncStopFeed(Session session, String feedId) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.stop_feed.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("feedId", feedId);

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed stop feed", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncIssueCredentials(Session session, String issuer, String holder, Map<String, Object> credentials, CredentialsOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.issue_credentials.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("issuer", issuer);
            message.put("holder", holder);
            message.put("credentials", Utils.getGson().toJson(credentials));
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed issuing credentials", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncVerifyCredentials(Session session, Map<String, Object> credentials, CredentialsOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.verify_credentials.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("credentials", Utils.getGson().toJson(credentials));
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed credentials verification", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncCreatePresentation(Session session, Map<String, Object> credentials, String subject, CredentialsOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.create_presentation.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("credentials", Utils.getGson().toJson(credentials));
            message.put("subject", subject);
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed create presentation", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncSignPresentation(Session session, Map<String, Object> presentation, String domain, String challenge, CredentialsOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.sign_presentation.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("presentation", Utils.getGson().toJson(presentation));
            message.put("domain", domain);
            message.put("challenge", challenge);
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed presentation signing", e);
            return new AccessError(null, e.toString());
        }
    }

    OperationResult syncVerifyPresentation(Session session, Map<String, Object> signedPresentation, String domain, String challenge, CredentialsOptions options) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.verify_presentation.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("presentation", Utils.getGson().toJson(signedPresentation));
            message.put("domain", domain);
            message.put("challenge", challenge);
            message.put("options", Utils.getGson().toJson(options));

            return sendRecordToTopicAndGetResponse(topicName, message);
        } catch (Exception e) {
            log.error("Failed verify presentation", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncPeerStatus(Session session, List<String> queuedReplies) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.peer_status.name());
            message.put("organization", session.getOrganization());
            message.put("account", session.getAccount());
            message.put("passive_replies", queuedReplies);

            return sendAuthenticated(message, session, Arrays.asList("organization", "account"));
        } catch (Exception e) {
            log.error("Failed status", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncResetConfig(Session session) {
        try {
            Map<String, Object> message = newMessage();
            message.put("type", RequestType.reset_config.name());
            return sendAuthenticated(message, session, Collections.emptyList());
        } catch (Exception e) {
            log.error("Failed resetting config", e);
            return new AccessError(null, e.toString());
        }
    }
}
