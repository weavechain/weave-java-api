package com.weavechain.api.client.ws;

import java.util.Map;
import java.util.function.BiConsumer;

public abstract class DefaultConnectionWrapper implements ConnectionWrapper {

    private BiConsumer<Map<String, Object>, String> handler;

    @Override
    public boolean isOpen() {
        return true;
    }

    @Override
    public abstract boolean send(Map<String, Object> request, String data);

    @Override
    public void receive(Map<String, Object> msg, String data) {
        if (handler != null) {
            handler.accept(msg, data);
        }
    }

    @Override
    public void registerOnMessage(BiConsumer<Map<String, Object>, String> handler) {
        this.handler = handler;
    }

    @Override
    public String remoteAddress() {
        return "127.0.0.1";
    }
}