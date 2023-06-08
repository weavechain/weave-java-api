package com.weavechain.api.config.transport;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class WSClientConfig {

    private String host;

    private int port;

    private boolean useWss;

    private String keyStore;

    private String keyStorePass;

    private String keyPass;

    private boolean encrypted = false;

    private Integer connectionLostTimeout = 300;

    private Integer connectRetryCount = 10;

    private Integer connectRetrySec = 5;

    public WSClientConfig host(String value) {
        this.host = value;
        return this;
    }

    public WSClientConfig port(int value) {
        this.port = value;
        return this;
    }

    public WSClientConfig useWss(boolean value) {
        this.useWss = value;
        return this;
    }

    public WSClientConfig keyStore(String value) {
        this.keyStore = value;
        return this;
    }

    public WSClientConfig keyStorePass(String value) {
        this.keyStorePass = value;
        return this;
    }

    public WSClientConfig keyPass(String value) {
        this.keyPass = value;
        return this;
    }

    public WSClientConfig encrypted(boolean value) {
        this.encrypted = value;
        return this;
    }

    public WSClientConfig connectRetryCount(int value) {
        this.connectRetryCount = value;
        return this;
    }

    public WSClientConfig connectRetrySec(int value) {
        this.connectRetrySec = value;
        return this;
    }

    public WSClientConfig copy() {
        return new WSClientConfig(
                host,
                port,
                useWss,
                keyStore,
                keyStorePass,
                keyPass,
                encrypted,
                connectionLostTimeout,
                connectRetryCount,
                connectRetrySec
        );
    }
}