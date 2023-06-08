package com.weavechain.api.feed;

import com.weavechain.api.client.WeaveAuthApi;
import com.weavechain.api.session.Session;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.operations.ComputeOptions;
import com.weavechain.core.operations.DeployOptions;
import com.weavechain.core.utils.CompletableFuture;

public interface WeaveFeedApi extends WeaveAuthApi {

    CompletableFuture<OperationResult> deployOracle(Session session, String oracleType, String targetBlockchain, String source, DeployOptions options);

    CompletableFuture<OperationResult> deployFeed(Session session, String image, DeployOptions options);

    CompletableFuture<OperationResult> removeFeed(Session session, String feedId);

    CompletableFuture<OperationResult> startFeed(Session session, String feedId, ComputeOptions options);

    CompletableFuture<OperationResult> stopFeed(Session session, String feedId);
}
