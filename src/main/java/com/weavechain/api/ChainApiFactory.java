package com.weavechain.api;

import com.weavechain.api.blockchain.WeaveChainApi;
import com.weavechain.api.blockchain.WeaveRemoteApi;
import com.weavechain.api.client.ApiClientV1;
import com.weavechain.api.client.WeaveApiClientV1;
import com.weavechain.api.client.http.HttpApiClient;
import com.weavechain.api.client.kafka.KafkaApiClient;
import com.weavechain.api.client.rabbitmq.RabbitMQApiClient;
import com.weavechain.api.client.ws.WSApiClient;
import com.weavechain.api.client.zmq.ZeroMQApiClient;
import com.weavechain.api.config.ChainClientConfig;
import com.weavechain.core.encrypt.KeysInfo;
import com.weavechain.core.encrypt.KeysProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ChainApiFactory {

    static final Logger logger = LoggerFactory.getLogger(ChainApiFactory.class);

    public static ApiClientV1 createApiClient(ChainClientConfig clientConfig) throws IllegalArgumentException {
        WeaveApiClientV1 apiClient = createApi(clientConfig);
        return new AggregatedApiClientV1(apiClient);
    }

    public static WeaveChainApi createWeaveChainClient(ChainClientConfig clientConfig) throws IllegalArgumentException {
        WeaveApiClientV1 apiClient = createApi(clientConfig);
        return new WeaveRemoteApi(apiClient);
    }

    private static WeaveApiClientV1 createApi(ChainClientConfig clientConfig) {
        WeaveApiClientV1 apiClient;

        ApiContext apiContext = initContext(clientConfig);

        //TODO: support multiple transports in parallel
        if (clientConfig.getHttp() != null) {
            apiClient = new HttpApiClient(clientConfig.getHttp(), apiContext);
        } else if (clientConfig.getWebsocket() != null) {
            apiClient = new WSApiClient(clientConfig.getWebsocket(), apiContext);
        } else if (clientConfig.getZeromq() != null) {
            apiClient = new ZeroMQApiClient(clientConfig.getZeromq(), apiContext);
        } else if (clientConfig.getKafka() != null) {
            apiClient = new KafkaApiClient(clientConfig.getKafka(), apiContext);
        } else if (clientConfig.getRabbitmq() != null) {
            apiClient = new RabbitMQApiClient(clientConfig.getRabbitmq(), apiContext);
        } else {
            throw new IllegalArgumentException("Invalid API configuration, missing transport");
        }
        return apiClient;
    }

    private static ApiContext initContext(ChainClientConfig clientConfig) {
        String privateKey = KeysProvider.readEncodedKey(clientConfig.getPrivateKey(), clientConfig.getPrivateKeyFile());
        String publicKey = KeysProvider.readEncodedKey(clientConfig.getPublicKey(), clientConfig.getPublicKeyFile());

        KeysInfo localKey = KeysInfo.fromEncodedKeyPair(privateKey, publicKey);

        return new ApiContext(
                localKey,
                Hex.decode(clientConfig.getSeed()),
                null,
                null,
                clientConfig.getIsDataIntegrityCheck(),
                false
        );
    }
}
