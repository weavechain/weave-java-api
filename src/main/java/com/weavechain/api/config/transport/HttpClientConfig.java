package com.weavechain.api.config.transport;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class HttpClientConfig {

    private String host;

    private int port;

    private boolean useHttps;

    private String keyStore;

    private String keyStorePass;

    private boolean encrypted = false;

    private boolean validateHeaders = true;

    public HttpClientConfig host(String value) {
        this.host = value;
        return this;
    }

    public HttpClientConfig port(int value) {
        this.port = value;
        return this;
    }

    public HttpClientConfig useHttps(boolean value) {
        this.useHttps = value;
        return this;
    }

    public HttpClientConfig keyStore(String value) {
        this.keyStore = value;
        return this;
    }

    public HttpClientConfig keyStorePass(String value) {
        this.keyStorePass = value;
        return this;
    }

    public HttpClientConfig encrypted(boolean value) {
        this.encrypted = value;
        return this;
    }

    public HttpClientConfig validateHeaders(boolean value) {
        this.validateHeaders = value;
        return this;
    }

    public HttpClientConfig copy() {
        return new HttpClientConfig(
                host,
                port,
                useHttps,
                keyStore,
                keyStorePass,
                encrypted,
                validateHeaders
        );
    }
}