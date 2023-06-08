package com.weavechain.api.client.kafka;

import com.weavechain.core.error.AccessError;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.error.Success;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import static com.weavechain.core.constants.KafkaConstants.PUBLIC_KEY_TOPIC;

/**
 * Gets public keys of other ChainNodes from a common public topic {@link com.weavechain.core.constants.KafkaConstants#PUBLIC_KEY_TOPIC}
 * Gives distinct public keys to this ChainNode's KafkaApiClient-s
 */
public class ServerPublicKeyResolver {

    private static final List<String> ALL_OBSERVED_SERVER_PUBLIC_KEYS = new ArrayList<>();
    private static final Object KEY_TOPIC_GUARD = new Object();
    private static int TAKEN_SERVER_PUBLIC_KEYS = 0;
    private static KafkaConsumer<String, String> PUBLIC_KEY_CONSUMER;

    private static final int MAX_RETRIES = 100;

    /**
     * If there are unassigned public keys -> return one of them
     * Otherwise -> repeatedly try to retrieve public keys; when successfully retrieved key(s) then return one of them
     */
    public static OperationResult syncPublicKey(String brokers, String ownServerPublicKey) {
        synchronized (KEY_TOPIC_GUARD) {
            if (ALL_OBSERVED_SERVER_PUBLIC_KEYS.size() > TAKEN_SERVER_PUBLIC_KEYS) {
                Success result = new Success(null, ALL_OBSERVED_SERVER_PUBLIC_KEYS.get(TAKEN_SERVER_PUBLIC_KEYS));
                TAKEN_SERVER_PUBLIC_KEYS++;
                return result;
            }

            int nRetry = 0;
            while (nRetry < MAX_RETRIES) {
                List<String> freshServerPublicKeys = getCurrentServerPublicKeys(brokers, ownServerPublicKey);
                if (freshServerPublicKeys.size() > ALL_OBSERVED_SERVER_PUBLIC_KEYS.size()) {
                    freshServerPublicKeys.stream().filter(pk -> !ALL_OBSERVED_SERVER_PUBLIC_KEYS.contains(pk)).forEach(ALL_OBSERVED_SERVER_PUBLIC_KEYS::add);
                    Success result = new Success(null, ALL_OBSERVED_SERVER_PUBLIC_KEYS.get(TAKEN_SERVER_PUBLIC_KEYS));
                    TAKEN_SERVER_PUBLIC_KEYS++;
                    return result;
                }
                try {
                    nRetry++;
                    Thread.sleep((int)(100 + (nRetry > 10 ? Math.sqrt(nRetry) * 500 : 0)));
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        return new AccessError(null, "Failed public key retrieval");
    }

    private static List<String> getCurrentServerPublicKeys(String brokers, String ownServerPublicKey) {
        KafkaConsumer<String, String> kafkaConsumer = getKafkaConsumer(brokers);
        TopicPartition tp = new TopicPartition(PUBLIC_KEY_TOPIC, 0);
        kafkaConsumer.assign(Collections.singleton(tp));
        kafkaConsumer.seek(tp, 0);
        ConsumerRecords<String, String> cr = kafkaConsumer.poll(Duration.ofMillis(100));
        List<String> freshServerPublicKeys = new ArrayList<>();
        cr.records(PUBLIC_KEY_TOPIC).forEach(r -> freshServerPublicKeys.add(r.value()));
        freshServerPublicKeys.remove(ownServerPublicKey);
        return freshServerPublicKeys;
    }

    private static synchronized KafkaConsumer<String, String> getKafkaConsumer(String brokers) {
        if (PUBLIC_KEY_CONSUMER == null) {
            Properties properties = new Properties();
            properties.setProperty(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, brokers);
            properties.setProperty(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
            properties.setProperty(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
            PUBLIC_KEY_CONSUMER = new KafkaConsumer<>(properties);
        }
        return PUBLIC_KEY_CONSUMER;
    }
}
