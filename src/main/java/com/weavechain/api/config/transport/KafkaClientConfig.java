package com.weavechain.api.config.transport;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class KafkaClientConfig {

    private String brokers;

    private String clientId;

    private String readTopic;

    private String writeTopic;

    private Boolean autocommit;

    public KafkaClientConfig brokers(String value) {
        this.brokers = value;
        return this;
    }

    public KafkaClientConfig clientId(String value) {
        this.clientId = value;
        return this;
    }

    public KafkaClientConfig readTopic(String value) {
        this.readTopic = value;
        return this;
    }

    public KafkaClientConfig writeTopic(String value) {
        this.writeTopic = value;
        return this;
    }

    public KafkaClientConfig autocommit(Boolean value) {
        this.autocommit = value;
        return this;
    }

    public KafkaClientConfig copy() {
        return new KafkaClientConfig(
                brokers,
                clientId,
                readTopic,
                writeTopic,
                autocommit
        );
    }
}