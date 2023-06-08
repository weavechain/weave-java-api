package com.weavechain.api.client;

import com.weavechain.api.session.Session;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.utils.CompletableFuture;

public interface WeaveAuthApi {

    boolean init();

    void whenInitialized(Runnable action);

    String getServerPublicKey();

    CompletableFuture<Session> login(String organization, String account, String scopes);

    CompletableFuture<Session> login(String organization, String account, String scopes, String credentials);

    CompletableFuture<Session> proxyLogin(String node, String organization, String account, String scopes);

    CompletableFuture<OperationResult> logout(Session session);

    CompletableFuture<Session> checkSession(Session session, String credentials);
}
