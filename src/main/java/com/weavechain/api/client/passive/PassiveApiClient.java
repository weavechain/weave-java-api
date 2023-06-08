package com.weavechain.api.client.passive;

import com.weavechain.api.ApiContext;
import com.weavechain.api.client.async.AsyncRequestsClient;
import com.weavechain.api.client.async.PendingRequest;
import com.weavechain.api.client.ws.ConnectionWrapper;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.Records;
import com.weavechain.core.encoding.ContentEncoder;
import com.weavechain.core.encoding.Encoding;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.error.Forward;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.error.OperationResultSerializer;
import com.weavechain.core.utils.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;

public class PassiveApiClient extends AsyncRequestsClient {

    static final Logger logger = LoggerFactory.getLogger(PassiveApiClient.class);

    private final ContentEncoder contentEncoder = Encoding.getDefaultContentEncoder();

    private final Map<String, CompletableFuture<OperationResult>> pendingRequests = Utils.newConcurrentHashMap();

    private final Map<String, BiConsumer<String, Records>> registeredListeners = Utils.newConcurrentHashMap();
    private final Map<String, DataLayout> tableLayouts = Utils.newConcurrentHashMap();

    private final PassiveApiClient.RequestsQueue queuedRequests;

    private ConnectionWrapper connection;

    public PassiveApiClient(ApiContext apiContext, PassiveApiClient.RequestsQueue queuedRequests, ConnectionWrapper conn) {
        super(apiContext);
        this.queuedRequests = queuedRequests;
        connection = conn;
        if (connection != null) {
            connection.registerOnMessage(this::onMessage);
        }
    }

    @Override
    public boolean init() {
        try {
            OperationResult remoteQuerySigKey = sigKey().get();
            String sigKey = remoteQuerySigKey.getStringData();
            initServerSigKey(sigKey);

            onInit();

            return true;
        } catch (Exception e) {
            logger.error("Could not retrieve server public key", e);
            return false;
        }
    }

    public void updateConnection(ConnectionWrapper conn) {
        connection = conn;
        if (connection != null) {
            connection.registerOnMessage(this::onMessage);
        }

    }

    protected void addPendingRequest(PendingRequest pending, String requestID) {
        pendingRequests.put(requestID, pending.getResult());
    }

    protected void sendRequest(String id, PendingRequest req, boolean isAuthenticated) {
        if (connection == null || !connection.isOpen()) {
            if (connection != null) {
                //TODO: reopen
            }

            queuedRequests.addRequest(getServerPublicKey(), req.toWire());
        } else {
            connection.send(req.getRequest(), req.toWire());
        }
    }

    public void onMessage(String message) {
        Map<String, Object> msg = Utils.getGson().fromJson(message, Map.class);
        onMessage(msg, message);
    }

    @SuppressWarnings("unchecked")
    public void onMessage(Map<String, Object> msg, String message) {
        try {

            String id = (String)msg.get("id");
            OperationResult reply = OperationResultSerializer.from(msg.get("reply"));
            String error = (String)msg.get("error");

            if (reply instanceof Forward) {
                String decryptedResult = decryptProxyParams(reply);
                reply = decryptedResult != null ? OperationResultSerializer.from(decryptedResult) : reply;
            }

            CompletableFuture<OperationResult> request = id != null ? pendingRequests.remove(id) : null;
            if (request != null) {
                if (error != null) {
                    logger.error("Error: " + error);
                }

                request.complete(reply);
            } else if (msg.get("event_id") != null) {
                String subscriptionId = ConvertUtils.convertToString(msg.get("sub_id"));
                BiConsumer<String, Records> onData = registeredListeners.get(subscriptionId);
                if (onData != null) {
                    DataLayout layout = tableLayouts.get(subscriptionId);
                    Records records = contentEncoder.decode(
                            ConvertUtils.convertToString(reply.getData()),
                            layout != null ? layout : DataLayout.DEFAULT
                    );
                    onData.accept(subscriptionId, records);
                } else {
                    logger.warn("Ignoring event for inexistent subscription " + subscriptionId);
                }
            } else {
                logger.warn("Ignoring reply for inexistent request " + id);
            }

        } catch (Exception e) {
            logger.error("Failed parsing message", e);
        }
    }

    public static class RequestsQueue {
        private final Map<String, List<String>> queuedRequests = Utils.newConcurrentHashMap();

        private final Map<String, List<String>> pendingReplies = Utils.newConcurrentHashMap();

        private final Map<String, List<String>> receivedReplies = Utils.newConcurrentHashMap();

        public void addRequest(String forPublicKey, String message) {
            List<String> toSend = queuedRequests.computeIfAbsent(forPublicKey, (k) -> new CopyOnWriteArrayList<>());
            toSend.add(message);
        }

        public void addPendingReply(String targetPublicKey, String message) {
            List<String> toSend = pendingReplies.computeIfAbsent(targetPublicKey, (k) -> new CopyOnWriteArrayList<>());
            toSend.add(message);
        }

        public void addReceivedReplies(String targetPublicKey, List<String> message) {
            List<String> toSend = receivedReplies.computeIfAbsent(targetPublicKey, (k) -> new CopyOnWriteArrayList<>());
            toSend.addAll(message);
        }

        //TODO: processing confirmation before removing?
        public List<String> readRequests(String publicKey) {
            return queuedRequests.remove(publicKey);
        }

        public List<String> readPendingReplies(String publicKey) {
            return pendingReplies.remove(publicKey);
        }

        public List<String> readReceivedReplies(String publicKey) {
            return pendingReplies.remove(publicKey);
        }
    }
}
