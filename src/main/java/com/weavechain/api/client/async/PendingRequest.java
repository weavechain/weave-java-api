package com.weavechain.api.client.async;

import com.weavechain.api.session.Session;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.utils.CompletableFuture;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

@Getter
@Setter
public class PendingRequest {

    public static final int DEFAULT_TIMEOUT_SEC = 60; //This must be at least 2 ping timeouts if using the network with passive nodes and HTTP transport

    private final CompletableFuture<OperationResult> result;

    private final CountDownLatch latch;

    private final boolean isAuthenticated;

    private final Session session;

    private Map<String, Object> request;

    private String message;

    private Runnable delayedPrepare;

    private final long arrivalTime;

    public PendingRequest(boolean isAuthenticated, Session session, Map<String, Object> request, String message, Runnable delayedPrepare, Integer timeoutSec) {
        this.isAuthenticated = isAuthenticated;
        this.session = session;
        this.request = request;
        this.message = message;
        this.delayedPrepare = delayedPrepare;
        this.arrivalTime = System.currentTimeMillis(); //TODO: use network time

        result = new CompletableFuture<>();
        result.orTimeout(timeoutSec != null ? timeoutSec : DEFAULT_TIMEOUT_SEC, TimeUnit.SECONDS);
        latch = new CountDownLatch(1);
    }

    public String toWire() {
        return message != null ? message : Utils.getGson().toJson(request);
    }
}
