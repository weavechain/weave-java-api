package com.weavechain.api.blockchain;

import com.weavechain.api.client.WeaveApiClientV1;
import com.weavechain.api.session.Session;
import com.weavechain.core.error.OperationResult;

import java.math.BigDecimal;
import java.util.List;
import com.weavechain.core.utils.CompletableFuture;

public class WeaveRemoteApi implements WeaveChainApi {

    public WeaveChainApi apiClient;

    public WeaveRemoteApi(WeaveApiClientV1 apiClient) {
        this.apiClient = apiClient;
    }

    @Override
    public boolean init() {
        return apiClient.init();
    }

    @Override
    public void whenInitialized(Runnable action) {
        apiClient.whenInitialized(action);
    }

    @Override
    public String getServerPublicKey() {
        return apiClient.getServerPublicKey();
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes) {
        return apiClient.login(organization, account, scopes);
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes, String credentials) {
        return apiClient.login(organization, account, scopes, credentials);
    }

    @Override
    public CompletableFuture<Session> proxyLogin(String node, String organization, String account, String scopes) {
        return apiClient.proxyLogin(node, organization, account, scopes);
    }

    @Override
    public CompletableFuture<OperationResult> logout(Session session) {
        return apiClient.logout(session);
    }

    @Override
    public CompletableFuture<Session> checkSession(Session session, String credentials) {
        return apiClient.checkSession(session, credentials);
    }

    @Override
    public CompletableFuture<OperationResult> createAccount(Session session, String publicKey) {
        return apiClient.createAccount(session, publicKey);
    }

    @Override
    public CompletableFuture<OperationResult> deploy(Session session, String contractType) {
        return apiClient.deploy(session, contractType);
    }

    @Override
    public CompletableFuture<OperationResult> call(Session session, String contractAddress, String scope, String function, byte[] data) {
        return apiClient.call(session, contractAddress, scope, function, data);
    }

    @Override
    public CompletableFuture<OperationResult> balance(Session session, String accountAddress, String scope, String token) {
        return apiClient.balance(session, accountAddress, scope, token);
    }

    @Override
    public CompletableFuture<OperationResult> transfer(Session session, String accountAddress, String scope, String token, BigDecimal amount) {
        return apiClient.transfer(session, accountAddress, scope, token, amount);
    }

    @Override
    public CompletableFuture<OperationResult> updateFees(Session session, String scope, String fees) {
        return apiClient.updateFees(session, scope, fees);
    }

    @Override
    public CompletableFuture<OperationResult> contractState(Session session, String address, String scope) {
        return apiClient.contractState(session, address, scope);
    }

    @Override
    public CompletableFuture<OperationResult> broadcastBlock(Session session, String scope, String block) {
        return apiClient.broadcastBlock(session, scope, block);
    }

    @Override
    public CompletableFuture<OperationResult> broadcastChain(Session session, String scope, List<String> blocks) {
        return apiClient.broadcastChain(session, scope, blocks);
    }
}
