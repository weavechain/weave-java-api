package com.weavechain.api.client;

import com.weavechain.api.WeaveDataApiV1;
import com.weavechain.api.admin.WeaveAdminApi;
import com.weavechain.api.blockchain.WeaveChainApi;
import com.weavechain.api.credentials.WeaveCredentialsApi;
import com.weavechain.api.lineage.WeaveLineageApi;
import com.weavechain.api.feed.WeaveFeedApi;
import com.weavechain.api.messaging.WeaveMessagingApi;

public interface ApiClientV1 extends
        WeaveDataApiV1,
        WeaveChainApi,
        WeaveAdminApi,
        WeaveLineageApi,
        WeaveFeedApi,
        WeaveCredentialsApi,
        WeaveMessagingApi
{
}
