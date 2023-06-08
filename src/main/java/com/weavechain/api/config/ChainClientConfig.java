package com.weavechain.api.config;

import com.weavechain.api.config.transport.*;
import com.weavechain.core.encoding.Utils;
import com.google.gson.stream.JsonReader;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ChainClientConfig {

    static final Logger logger = LoggerFactory.getLogger(ChainClientConfig.class);

    private String organization;

    private String account;

    private String seed;

    private String publicKey;

    private String publicKeyFile; //hex encoded or base64 encoded

    private String privateKey;

    private String privateKeyFile;

    private HttpClientConfig http;

    private WSClientConfig websocket;

    private ZeroMQClientConfig zeromq;

    private KafkaClientConfig kafka;

    private RabbitMQClientConfig rabbitmq;

    private Boolean inMem = false;

    /** if true then client computes hash of sent records, signs it and sends to server together with the records
     * Server can assure that it received unchanged data from expected client */
    private Boolean isDataIntegrityCheck;

    public ChainClientConfig organization(String value) {
        this.organization = value;
        return this;
    }

    public ChainClientConfig account(String value) {
        this.account = value;
        return this;
    }

    public ChainClientConfig seed(String value) {
        this.seed = value;
        return this;
    }

    public ChainClientConfig privateKey(String value) {
        this.privateKey = value;
        return this;
    }

    public ChainClientConfig privateKeyFile(String value) {
        this.privateKeyFile = value;
        return this;
    }

    public ChainClientConfig publicKey(String value) {
        this.publicKey = value;
        return this;
    }

    public ChainClientConfig publicKeyFile(String value) {
        this.publicKeyFile = value;
        return this;
    }

    public ChainClientConfig http(HttpClientConfig value) {
        this.http = value != null ? value.copy() : null;
        return this;
    }

    public ChainClientConfig ws(WSClientConfig value) {
        this.websocket = value != null ? value.copy() : null;
        return this;
    }

    public ChainClientConfig zeroMQ(ZeroMQClientConfig value) {
        this.zeromq = value != null ? value.copy() : null;
        return this;
    }

    public ChainClientConfig kafka(KafkaClientConfig value) {
        this.kafka = value != null ? value.copy() : null;
        return this;
    }

    public ChainClientConfig rabbitMQ(RabbitMQClientConfig value) {
        this.rabbitmq = value != null ? value.copy() : null;
        return this;
    }

    public ChainClientConfig inmem(boolean value) {
        this.inMem = value;
        return this;
    }

    public ChainClientConfig isDataIntegrityCheck(boolean value) {
        this.isDataIntegrityCheck = value;
        return this;
    }

    public static ChainClientConfig readConfig(String configFile) {
        try {
            JsonReader reader = new JsonReader(new FileReader(configFile));
            return Utils.getGson().fromJson(reader, ChainClientConfig.class);
        } catch (Exception e) {
            logger.error(String.format("Failed loading chain config %s", configFile), e);
            return null;
        }
    }

    public static ChainClientConfig parseConfig(String config) {
        try {
            return Utils.getGson().fromJson(config, ChainClientConfig.class);
        } catch (Exception e) {
            logger.error("Failed reading chain config", e);
            return null;
        }
    }

    public ChainClientConfig copy() {
        return new ChainClientConfig(
                organization,
                account,
                seed,
                publicKey,
                publicKeyFile,
                privateKey,
                privateKeyFile,
                http,
                websocket,
                zeromq,
                kafka,
                rabbitmq,
                inMem,
                isDataIntegrityCheck
        );
    }

    public ChainClientConfig merge(ChainClientConfig config) {
        return new ChainClientConfig(
                config.organization != null ? config.organization : organization,
                config.account != null ? config.account : account,
                config.seed != null ? config.seed : seed,
                config.publicKey != null ? config.publicKey : publicKey,
                config.publicKeyFile != null ? config.publicKeyFile : publicKeyFile,
                config.privateKey != null ? config.privateKey : privateKey,
                config.privateKeyFile != null ? config.privateKeyFile : privateKeyFile,
                config.http != null ? config.http : http,
                config.websocket != null ? config.websocket : websocket,
                config.zeromq != null ? config.zeromq : zeromq,
                config.kafka != null ? config.kafka : kafka,
                config.rabbitmq != null ? config.rabbitmq : rabbitmq,
                config.inMem != null ? config.inMem : inMem,
                config.isDataIntegrityCheck != null ? config.isDataIntegrityCheck : isDataIntegrityCheck
        );
    }
}