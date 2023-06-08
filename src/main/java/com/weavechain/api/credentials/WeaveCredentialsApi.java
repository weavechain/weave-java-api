package com.weavechain.api.credentials;

import com.weavechain.api.client.WeaveAuthApi;
import com.weavechain.api.session.Session;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.operations.CredentialsOptions;
import com.weavechain.core.utils.CompletableFuture;

import java.util.Map;

public interface WeaveCredentialsApi extends WeaveAuthApi {

    String getUserDID();

    String generateDID(String method);

    CompletableFuture<OperationResult> issueCredentials(Session session, String issuer, String holder, Map<String, Object> credentials, CredentialsOptions options);

    CompletableFuture<OperationResult> verifyCredentials(Session session, Map<String, Object> credentials, CredentialsOptions options);

    CompletableFuture<OperationResult> createPresentation(Session session, Map<String, Object> credentials, String subject, CredentialsOptions options);

    CompletableFuture<OperationResult> signPresentation(Session session, Map<String, Object> presentation, String domain, String challenge, CredentialsOptions options);

    CompletableFuture<OperationResult> verifyPresentation(Session session, Map<String, Object> signedPresentation, String domain, String challenge, CredentialsOptions options);

    //consider adding revoke for certain cases?
}
