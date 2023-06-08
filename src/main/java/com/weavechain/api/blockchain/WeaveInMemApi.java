package com.weavechain.api.blockchain;

import com.weavechain.api.session.Session;
import com.weavechain.core.error.OperationResult;

import java.math.BigDecimal;
import java.util.List;
import com.weavechain.core.utils.CompletableFuture;

public class WeaveInMemApi implements WeaveChainApi {

    public WeaveChainApi inMemChain;

    public WeaveInMemApi(WeaveChainApi chain) {
        this.inMemChain = chain;
    }

    @Override
    public boolean init() {
        return inMemChain.init();
    }

    @Override
    public void whenInitialized(Runnable action) {
        inMemChain.whenInitialized(action);
    }

    @Override
    public String getServerPublicKey() {
        return inMemChain.getServerPublicKey();
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes) {
        return inMemChain.login(organization, account, scopes);
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes, String credentials) {
        return inMemChain.login(organization, account, scopes, credentials);
    }

    @Override
    public CompletableFuture<Session> proxyLogin(String node, String organization, String account, String scopes) {
        return inMemChain.proxyLogin(node, organization, account, scopes);
    }

    @Override
    public CompletableFuture<OperationResult> logout(Session session) {
        return inMemChain.logout(session);
    }

    @Override
    public CompletableFuture<Session> checkSession(Session session, String credentials) {
        return inMemChain.checkSession(session, credentials);
    }

    @Override
    public CompletableFuture<OperationResult> createAccount(Session session, String publicKey) {
        return inMemChain.createAccount(session, publicKey);
    }

    @Override
    public CompletableFuture<OperationResult> deploy(Session session, String contractType) {
        return inMemChain.deploy(session, contractType);
    }

    @Override
    public CompletableFuture<OperationResult> call(Session session, String contractAddress, String scope, String function, byte[] data) {
        return inMemChain.call(session, contractAddress, scope, function, data);
    }

    @Override
    public CompletableFuture<OperationResult> balance(Session session, String accountAddress, String scope, String token) {
        return inMemChain.balance(session, accountAddress, scope, token);
    }

    @Override
    public CompletableFuture<OperationResult> transfer(Session session, String accountAddress, String scope, String token, BigDecimal amount) {
        return inMemChain.transfer(session, accountAddress, scope, token, amount);
    }

    @Override
    public CompletableFuture<OperationResult> updateFees(Session session, String scope, String fees) {
        return inMemChain.updateFees(session, scope, fees);
    }

    @Override
    public CompletableFuture<OperationResult> contractState(Session session, String address, String scope) {
        return inMemChain.contractState(session, address, scope);
    }

    @Override
    public CompletableFuture<OperationResult> broadcastBlock(Session session, String scope, String block) {
        return inMemChain.broadcastBlock(session, scope, block);
    }

    @Override
    public CompletableFuture<OperationResult> broadcastChain(Session session, String scope, List<String> blocks) {
        return inMemChain.broadcastChain(session, scope, blocks);
    }
}
