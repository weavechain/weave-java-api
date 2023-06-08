package com.weavechain.api.client.ws;

import java.util.Map;
import java.util.function.BiConsumer;

public interface ConnectionWrapper {

    boolean isOpen();

    boolean send(Map<String, Object> request, String data);

    void receive(Map<String, Object> msg, String data);

    void registerOnMessage(BiConsumer<Map<String, Object>, String> handler);

    String remoteAddress();
}