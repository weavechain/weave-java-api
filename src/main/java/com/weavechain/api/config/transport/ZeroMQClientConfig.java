package com.weavechain.api.config.transport;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ZeroMQClientConfig {

    private boolean isIPC;

    private String host;

    private int port;

    public ZeroMQClientConfig ipc(boolean value) {
        this.isIPC = value;
        return this;
    }

    public ZeroMQClientConfig host(String value) {
        this.host = value;
        return this;
    }

    public ZeroMQClientConfig port(int value) {
        this.port = value;
        return this;
    }

    public ZeroMQClientConfig copy() {
        return new ZeroMQClientConfig(isIPC, host, port);
    }
}