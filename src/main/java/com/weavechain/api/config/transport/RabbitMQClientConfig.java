package com.weavechain.api.config.transport;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RabbitMQClientConfig {

    private String host;

    private Integer port;

    private boolean useSSL;

    private String user;

    private String password;

    private String mainQueueName;

    private String keyStore;

    private String keyStorePass;

    private String keyPass;

    public RabbitMQClientConfig host(String value) {
        this.host = value;
        return this;
    }

    public RabbitMQClientConfig port(Integer value) {
        this.port = value;
        return this;
    }

    public RabbitMQClientConfig useSSL(boolean value) {
        this.useSSL = value;
        return this;
    }

    public RabbitMQClientConfig user(String value) {
        this.user = value;
        return this;
    }

    public RabbitMQClientConfig password(String value) {
        this.password = value;
        return this;
    }

    public RabbitMQClientConfig mainQueueName(String value) {
        this.mainQueueName = value;
        return this;
    }

    public RabbitMQClientConfig keyStore(String value) {
        this.keyStore = value;
        return this;
    }

    public RabbitMQClientConfig keyStorePass(String value) {
        this.keyStorePass = value;
        return this;
    }

    public RabbitMQClientConfig keyPass(String value) {
        this.keyPass = value;
        return this;
    }

    public RabbitMQClientConfig copy() {
        return new RabbitMQClientConfig(
                host,
                port,
                useSSL,
                user,
                password,
                mainQueueName,
                keyStore,
                keyStorePass,
                keyPass
        );
    }
}