package com.weavechain.api.client.ws;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

public class WSClient extends WebSocketClient {

    static final Logger logger = LoggerFactory.getLogger(WSClient.class);

    private final WSApiClient apiClient;

    public WSClient(URI uri, WSApiClient apiClient) {
        super(uri);
        this.apiClient = apiClient;
        setTcpNoDelay(true);
    }

    @Override
    public void onOpen(ServerHandshake handshake) {
        apiClient.onOpen();
    }

    @Override
    public void onMessage(String message) {
        apiClient.onMessage(message);
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        apiClient.onClose(code, reason, remote);
    }

    @Override
    public void onError(Exception ex) {
        apiClient.onError(ex);
    }
}
