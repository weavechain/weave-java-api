package com.weavechain.api.mainchain;

import com.weavechain.api.blockchain.WeaveChainApi;
import com.weavechain.api.session.Session;
import com.weavechain.core.error.OperationResult;

import java.math.BigInteger;
import java.util.List;

public interface MainChainApi {

    boolean init();

    void sync(WeaveChainApi weaveChainApi);

    boolean waitSync(int timeoutMs);

    OperationResult withdraw(WeaveChainApi weaveChainApi, Session session, String account, String token, BigInteger amount);

    OperationResult authorizeAccount(Session session, String account, String token, String authorizedAddress, byte[] signature);

    void updateAccountMetadata(String account, AccountMetadata metadata);

    AccountMetadata getAccountMetadata(String account);

    void publishDataset(DatasetMetadata metadata);

    List<DatasetMetadata> getDatasets(DatasetFilter filter);

    boolean mapAccountAsync(String ethAccount, String publicKey, String token);
}
