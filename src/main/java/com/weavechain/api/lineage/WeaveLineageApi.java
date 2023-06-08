package com.weavechain.api.lineage;

import com.weavechain.api.client.WeaveAuthApi;
import com.weavechain.api.session.Session;
import com.weavechain.core.data.filter.Filter;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.operations.HistoryOptions;
import com.weavechain.core.operations.OutputOptions;
import com.weavechain.core.utils.CompletableFuture;

import java.util.Map;

public interface WeaveLineageApi extends WeaveAuthApi {

    CompletableFuture<OperationResult> taskLineage(Session session, String taskId);

    CompletableFuture<OperationResult> hashCheckpoint(Session session);

    CompletableFuture<OperationResult> hashCheckpoint(Session session, Boolean enable);

    CompletableFuture<OperationResult> verifyTaskLineage(Session session, Map<String, Object> lineageData);

    CompletableFuture<OperationResult> taskOutputData(Session session, String taskId, OutputOptions options);

    CompletableFuture<OperationResult> history(Session session, String scope, String table, Filter filter, HistoryOptions options);

    CompletableFuture<OperationResult> writers(Session session, String scope, String table, Filter filter);

    CompletableFuture<OperationResult> tasks(Session session, String scope, String table, Filter filter);

    CompletableFuture<OperationResult> lineage(Session session, String scope, String table, Filter filter);
}
