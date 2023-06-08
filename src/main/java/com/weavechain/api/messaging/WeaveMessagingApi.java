package com.weavechain.api.messaging;

import com.weavechain.api.client.WeaveAuthApi;
import com.weavechain.api.session.Session;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.operations.MessageOptions;
import com.weavechain.core.utils.CompletableFuture;

public interface WeaveMessagingApi extends WeaveAuthApi {

    CompletableFuture<OperationResult> postMessage(Session session, String targetInboxKey, String message, MessageOptions options);

    CompletableFuture<OperationResult> pollMessages(Session session, String inboxKey, MessageOptions options);
}
