package com.weavechain.api.client.async;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.weavechain.api.ApiContext;
import com.weavechain.api.client.WeaveApiClientV1;
import com.weavechain.api.client.passive.PassiveApiClient;
import com.weavechain.api.session.Session;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.error.AccessError;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.requests.RequestType;
import com.weavechain.core.utils.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public abstract class AsyncClient extends WeaveApiClientV1 {

    static final Logger logger = LoggerFactory.getLogger(AsyncClient.class);

    public static final String TLS = "TLS";

    private static final int ENCODE_THREADS = 4; //use 0 for no parallel prepare. Move to internal config

    private static final int ENCODE_WAIT_TIME_SEC = 300;

    //2022.08 - switching to static, share encoding threads when having multiple clients. To review depending on usage
    private static final ExecutorService encodeExecutor = ENCODE_THREADS == 0
            ? null
            : Executors.newFixedThreadPool(ENCODE_THREADS, new ThreadFactoryBuilder().setNameFormat("WeaveApiEnc-%d").setDaemon(true).build());

    private static final ExecutorService unauthDispatchExecutor = Executors.newCachedThreadPool(new ThreadFactoryBuilder().setNameFormat("WeaveApiEnc-%d").setDaemon(true).build());

    private static final Map<String, ExecutorService> dispatchExecutors = Utils.newConcurrentHashMap();

    public AsyncClient(ApiContext apiContext) {
        super(apiContext);
    }

    private PendingRequest prepareRequest(PendingRequest pending, Map<String, Object> request) {
        if (pending.getDelayedPrepare() != null) {
            pending.getDelayedPrepare().run();
        }

        if (pending.isAuthenticated()) {
            addAuthParams(request, pending.getSession());
        }

        String requestID = Utils.generateUUID();
        request.put("id", requestID);
        addPendingRequest(pending, requestID);

        pending.setMessage(Utils.getMapJsonAdapter().toJson(request));

        return pending;
    }

    protected CompletableFuture<OperationResult> sendRequest(RequestType requestType, Map<String, Object> request, boolean isAuthenticated, Session session, Runnable delayedPrepare, Integer timeoutSec) {
        request.put("type", requestType.name());
        String feeLimits = getFeeLimits(requestType);
        if (feeLimits != null) {
            request.put("feeLimit", feeLimits);
        }

        if (session == null || session.getProxyNode() == null) {
            return sendRawRequest(request, isAuthenticated, session, delayedPrepare, timeoutSec);
        } else {
            Map<String, Object> fwdRequest = encryptProxyParams(session, (String)request.get("type"), request, session.getProxyNode(), session.getTempKey());
            fwdRequest.put("type", RequestType.forwarded_request.name());
            if (isAuthenticated) {
                addAuthParams(fwdRequest, session);
            }

            CompletableFuture<OperationResult> reply = new CompletableFuture<>();
            sendRawRequest(fwdRequest, isAuthenticated, session, delayedPrepare, timeoutSec).whenComplete((data, e) -> {
                if (e != null) {
                    logger.error("Failed forwarding", e);
                    reply.complete(null);
                } else {
                    try {
                        reply.complete(data);
                    } catch (Exception ex) {
                        reply.complete(null);
                    }
                }
            });

            return reply;
        }
    }

    private ExecutorService getDispatchExecutor(Session session) {
        if (session != null && session.getApiKey() != null) {
            return dispatchExecutors.computeIfAbsent(session.getApiKey(), (k) -> Executors.newSingleThreadExecutor(new ThreadFactoryBuilder().setNameFormat("WeaveApiDisp-" + session.getApiKey()).setDaemon(true).build()));
        } else {
            return unauthDispatchExecutor;
        }
    }

    protected CompletableFuture<OperationResult> sendRawRequest(Map<String, Object> request, boolean isAuthenticated, Session session, Runnable delayedPrepare, Integer timeoutSec) {
        PendingRequest pending = new PendingRequest(isAuthenticated, session, null, null, delayedPrepare, timeoutSec);
        if (ENCODE_THREADS == 0 || this instanceof PassiveApiClient) {
            prepareRequest(pending, request);
            sendRequest((String)request.get("id"), pending, isAuthenticated);
        } else {
            //TODO: max in flight messages

            encodeExecutor.submit(() -> {
                try {
                    prepareRequest(pending, request);
                } catch (Exception e) {
                    logger.error("Failed preparing request", e);
                } finally {
                    pending.getLatch().countDown();
                }
            });

            getDispatchExecutor(session).submit(() -> {
                try {
                    if (pending.getLatch().getCount() == 0 || pending.getLatch().await(ENCODE_WAIT_TIME_SEC, TimeUnit.SECONDS)) {
                        sendRequest((String)request.get("id"), pending, isAuthenticated);
                        return pending.getResult();
                    } else {
                        String msg = "Timeout while encoding message";
                        logger.error(msg);
                        return new AccessError(null, msg);
                    }
                } catch (Exception e) {
                    logger.error("Failed dispatch", e);
                    return new AccessError(null, e.toString());
                }
            });
        }

        return pending.getResult();
    }

    protected abstract void addPendingRequest(PendingRequest pending, String requestID);

    protected abstract void sendRequest(String id, PendingRequest req, boolean isAuthenticated);
}
