package com.weavechain.api.admin;

import com.weavechain.api.client.WeaveAuthApi;
import com.weavechain.api.session.Session;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.operations.TermsOptions;
import com.weavechain.core.utils.CompletableFuture;

import java.util.List;
import java.util.Map;
import java.util.Set;

public interface WeaveAdminApi extends WeaveAuthApi {

    CompletableFuture<OperationResult> terms(Session session, TermsOptions options);

    CompletableFuture<OperationResult> peerStatus(Session session, List<String> queuedReplies);

    CompletableFuture<OperationResult> forwardedRequest(Session session, Map<String, Object> msg);

    CompletableFuture<OperationResult> getSidechainDetails(Session session);

    //TODO: getUserDetails

    CompletableFuture<OperationResult> getNodes(Session session);

    CompletableFuture<OperationResult> getScopes(Session session);

    CompletableFuture<OperationResult> getTables(Session session, String scope);

    CompletableFuture<OperationResult> getTableDefinition(Session session, String scope, String table);

    CompletableFuture<OperationResult> getNodeConfig(Session session, String nodePublicKey);

    CompletableFuture<OperationResult> getAccountNotifications(Session session);

    CompletableFuture<OperationResult> updateLayout(Session session, String scope, String table, String layout);

    CompletableFuture<OperationResult> updateConfig(Session session, String path, Map<String, Object> values);

    CompletableFuture<OperationResult> grantRole(Session session, String account, Set<String> roles);

    CompletableFuture<OperationResult> createUserAccount(Session session, String targetOrganization, String newAccount, String publicKey, Set<String> roles, boolean isSuperAdmin);

    CompletableFuture<OperationResult> resetConfig(Session session);
}
