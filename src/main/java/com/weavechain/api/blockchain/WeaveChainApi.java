package com.weavechain.api.blockchain;

import com.weavechain.api.client.WeaveAuthApi;
import com.weavechain.api.session.Session;
import com.weavechain.core.error.OperationResult;

import java.math.BigDecimal;
import java.util.List;
import com.weavechain.core.utils.CompletableFuture;

public interface WeaveChainApi extends WeaveAuthApi {

    CompletableFuture<OperationResult> createAccount(Session session, String publicKey);

    CompletableFuture<OperationResult> deploy(Session session, String contractType);

    CompletableFuture<OperationResult> call(Session session, String contractAddress, String scope, String function, byte[] data);

    CompletableFuture<OperationResult> balance(Session session, String accountAddress, String scope, String token);

    CompletableFuture<OperationResult> transfer(Session session, String accountAddress, String scope, String token, BigDecimal amount);

    CompletableFuture<OperationResult> updateFees(Session session, String scope, String fees);

    CompletableFuture<OperationResult> contractState(Session session, String contractAddress, String scope);

    //TODO: move to private API, binary transport instead of json
    CompletableFuture<OperationResult> broadcastBlock(Session session, String scope, String block);

    CompletableFuture<OperationResult> broadcastChain(Session session, String scope, List<String> blocks);
}
