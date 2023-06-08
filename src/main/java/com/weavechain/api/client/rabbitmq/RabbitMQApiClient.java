package com.weavechain.api.client.rabbitmq;

import com.weavechain.api.ApiContext;
import com.weavechain.api.auth.BLSKeyPair;
import com.weavechain.api.client.WeaveApiClientV1;
import com.weavechain.api.client.async.AsyncClient;
import com.weavechain.api.config.transport.RabbitMQClientConfig;
import com.weavechain.api.pre.ProxyEncryptedData;
import com.weavechain.api.session.Session;
import com.weavechain.core.consensus.ConsensusMessage;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.filter.Filter;
import com.weavechain.core.data.Records;
import com.weavechain.core.encoding.ContentEncoder;
import com.weavechain.core.encoding.Encoding;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.KeysProvider;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.file.FileFormat;
import com.weavechain.core.operations.*;
import com.weavechain.core.requests.RequestType;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import org.bitcoinj.base.Base58;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.*;
import java.util.function.BiConsumer;

import com.weavechain.core.utils.CompletableFuture;

public class RabbitMQApiClient extends WeaveApiClientV1 {

    static final Logger logger = LoggerFactory.getLogger(RabbitMQApiClient.class);

    private final RabbitMQClientConfig config;

    private Connection connection;

    private Channel mainChannel;

    private final ContentEncoder contentEncoder = Encoding.getDefaultContentEncoder();

    private final Map<String, CompletableFuture<OperationResult>> pendingRequests = Utils.newConcurrentHashMap();

    public RabbitMQApiClient(RabbitMQClientConfig config, ApiContext apiContext) {
        super(apiContext);
        this.config = config.copy();
    }

    @Override
    public boolean init() {
        try {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost(Utils.parseHost(config.getHost()));
            factory.setPort(config.getPort());
            factory.setUsername(config.getUser());
            factory.setPassword(config.getPassword());

            if (config.isUseSSL()) {
                initSSL(factory, config);
            }

            //TODO: multiple connections
            connection = factory.newConnection();
            mainChannel = connection.createChannel();
            mainChannel.queueDeclare(config.getMainQueueName(), false, false, false, null);

            keysInit();

            return true;
        } catch (Exception e) {
            logger.error("Could not retrieve server public key", e);
            return false;
        }
    }

    private void initSSL(ConnectionFactory factory, RabbitMQClientConfig config) {
        try {
            SocketFactory socketFactory;

            if (config.getKeyStore() != null) {
                KeyStore ks = KeyStore.getInstance("JKS");
                File kf = new File(config.getKeyStore());
                ks.load(new FileInputStream(kf), config.getKeyStorePass().toCharArray());

                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, (config.getKeyPass() != null ? config.getKeyPass() : "").toCharArray());

                TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                tmf.init(ks);

                SSLContext context = SSLContext.getInstance(AsyncClient.TLS);
                context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

                socketFactory = context.getSocketFactory();
            } else {
                SSLContext context = SSLContext.getInstance(AsyncClient.TLS);
                context.init(null, null, null);
                socketFactory = context.getSocketFactory();
            }

            factory.setSocketFactory(socketFactory);
        } catch (Exception e) {
            logger.error("Failed initializing SSL", e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> version() {
        Map<String, Object> request = new HashMap<>();
        return sendRequest(RequestType.version, request);
    }

    @Override
    public CompletableFuture<OperationResult> ping() {
        Map<String, Object> request = new HashMap<>();
        return sendRequest(RequestType.ping, request);
    }

    @Override
    public CompletableFuture<OperationResult> publicKey() {
        Map<String, Object> request = new HashMap<>();
        return sendRequest(RequestType.public_key, request);
    }

    @Override
    public CompletableFuture<OperationResult> sigKey() {
        return sigKey(null);
    }

    @Override
    public CompletableFuture<OperationResult> sigKey(String account) {
        Map<String, Object> request = new HashMap<>();
        if (account != null) {
            request.put("account", account);
        }
        return sendRequest(RequestType.sig_key, request);
    }

    @Override
    public CompletableFuture<OperationResult> rsaKey() {
        return rsaKey(null);
    }

    @Override
    public CompletableFuture<OperationResult> rsaKey(String account) {
        Map<String, Object> request = new HashMap<>();
        if (account != null) {
            request.put("account", account);
        }
        return sendRequest(RequestType.rsa_key, request);
    }

    @Override
    public CompletableFuture<OperationResult> blsKey() {
        return blsKey(null);
    }

    @Override
    public CompletableFuture<OperationResult> blsKey(String account) {
        Map<String, Object> request = new HashMap<>();
        if (account != null) {
            request.put("account", account);
        }
        return sendRequest(RequestType.bls_key, request);
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes) {
        return login(organization, account, scopes, null);
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes, String credentials) {
        String toSign = organization + "\n" + getClientPublicKey() + "\n" + scopes;
        byte[] iv = KeysProvider.generateIV();
        String signature = signString(toSign, iv);

        Map<String, Object> request = new HashMap<>();
        request.put("organization", organization);
        request.put("account", account);
        request.put("scopes", scopes);
        if (credentials != null) {
            request.put("credentials", credentials);
        }
        request.put("signature", signature);
        request.put("x-key", getClientPublicKey());
        request.put("x-sig-key", KeysProvider.derivePublicSigKey(getApiContext().getClientPrivateKey()));
        request.put("x-rsa-key", KeysProvider.derivePublicRSAKey(getApiContext().getClientPrivateKey()));
        BLSKeyPair blsKeyPair = getBlsKeyPair();
        if (blsKeyPair != null && blsKeyPair.getPublicKey() != null) {
            request.put("x-bls-key", Base58.encode(blsKeyPair.getPublicKey()));
        }
        request.put("x-iv", Hex.toHexString(iv));
        addDelegateSignature(request);

        CompletableFuture<Session> sess = new CompletableFuture<>();
        sendRequest(RequestType.login, request).whenComplete((data, e) -> {
            if (e != null) {
                logger.error("Failed login", e);
                sess.complete(null);
            } else {
                try {
                    sess.complete(Session.parse(data.getData(), getApiContext()));
                } catch (Exception ex) {
                    //logger.error("Failed session deserialization from " + data, ex);
                    sess.complete(null);
                }
            }
        });
        return sess;
    }

    @Override
    public CompletableFuture<Session> proxyLogin(String node, String organization, String account, String scopes) {
        Map<String, Object> request = buildProxyLoginParams(node, organization, account, scopes);

        CompletableFuture<Session> sess = new CompletableFuture<>();
        sendRequest(RequestType.proxy_login, request).whenComplete((data, e) -> {
            if (e != null) {
                logger.error("Failed login", e);
                sess.complete(null);
            } else {
                try {
                    sess.complete(Session.parse(data.getData(), getApiContext()));
                } catch (Exception ex) {
                    //logger.error("Failed session deserialization from " + data, ex);
                    sess.complete(null);
                }
            }
        });
        return sess;
    }

    @Override
    public CompletableFuture<OperationResult> logout(Session session) {
        Map<String, Object> request = new TreeMap<>(); //order is important for signing
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        addAuthParams(request, session);
        return sendRequest(RequestType.logout, request);
    }

    @Override
    public CompletableFuture<OperationResult> terms(Session session, TermsOptions options) {
        Map<String, Object> request = new TreeMap<>(); //order is important for signing
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        String termsOptions = Utils.getGson().toJson(options);
        request.put("options", termsOptions);
        request.put("signature", sign(termsOptions));
        addAuthParams(request, session);
        return sendRequest(RequestType.terms, request);
    }

    @Override
    public CompletableFuture<OperationResult> status(Session session) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        addAuthParams(request, session);
        return sendRequest(RequestType.status, request);
    }

    @Override
    public CompletableFuture<OperationResult> createTable(Session session, String scope, String table, CreateOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.create, request);
    }

    @Override
    public CompletableFuture<OperationResult> dropTable(Session session, String scope, String table, DropOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.drop, request);
    }

    @Override
    public CompletableFuture<OperationResult> updateLayout(Session session, String scope, String table, String layout) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        request.put("layout", layout);
        addAuthParams(request, session);
        return sendRequest(RequestType.update_layout, request);
    }

    @Override
    public CompletableFuture<OperationResult> write(Session session, String scope, Records records, WriteOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());

        addIntegritySignatureIfConfigured(records, session, scope, request);

        DataLayout layout = getTableLayout(session, scope, records.getTable());
        ContentEncoder encoder = layout != null ? contentEncoder : Encoding.getJsonContentEncoder();
        if (encoder != Encoding.getDefaultContentEncoder()) {
            request.put("enc", encoder.getType());
        }

        request.put("table", records.getTable());
        request.put("records", encoder.encode(records, layout));
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.write, request);
    }

    @Override
    public CompletableFuture<OperationResult> read(Session session, String scope, String table, Filter filter, ReadOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.read, request);
    }

    @Override
    public CompletableFuture<OperationResult> count(Session session, String scope, String table, Filter filter, ReadOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.count, request);
    }

    @Override
    public CompletableFuture<OperationResult> delete(Session session, String scope, String table, Filter filter, DeleteOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.delete, request);
    }

    @Override
    public CompletableFuture<OperationResult> hashes(Session session, String scope, String table, Filter filter, ReadOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.hashes, request);
    }

    @Override
    public CompletableFuture<OperationResult> downloadTable(Session session, String scope, String table, Filter filter, FileFormat format, ReadOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        request.put("format", format.name());
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.download_table, request);
    }

    @Override
    public CompletableFuture<OperationResult> downloadDataset(Session session, String did, ReadOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("did", did);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.download_dataset, request);
    }

    @Override
    public CompletableFuture<OperationResult> publishDataset(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String scope, String table, Filter filter, FileFormat format, BigDecimal price, String token, Long pageorder, PublishDatasetOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("did", did);
        request.put("name", name);
        request.put("description", description);
        request.put("license", license);
        request.put("metadata", metadata);
        request.put("weave", weave);
        request.put("full_description", fullDescription);
        request.put("logo", logo);
        request.put("category", category);
        request.put("scope", scope);
        request.put("table", table);
        request.put("format", format.name());
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        request.put("price", price);
        request.put("token", token);
        request.put("pageorder", pageorder);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.publish_dataset, request);
    }

    @Override
    public CompletableFuture<OperationResult> enableProduct(Session session, String did, String productType, Boolean active) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("did", did);
        request.put("productType", productType);
        request.put("active", active);

        addAuthParams(request, session);
        return sendRequest(RequestType.enable_product, request);
    }

    @Override
    public CompletableFuture<OperationResult> runTask(Session session, String did, ComputeOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("did", did);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.run_task, request);
    }

    @Override
    public CompletableFuture<OperationResult> publishTask(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String task, BigDecimal price, String token, Long pageorder, PublishTaskOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("did", did);
        request.put("name", name);
        request.put("description", description);
        request.put("license", license);
        request.put("metadata", metadata);
        request.put("weave", weave);
        request.put("full_description", fullDescription);
        request.put("logo", logo);
        request.put("category", category);
        request.put("task", task);
        request.put("price", price);
        request.put("token", token);
        request.put("pageorder", pageorder);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.publish_task, request);
    }

    @Override
    public CompletableFuture<OperationResult> subscribe(Session session, String scope, String table, Filter filter, SubscribeOptions options, BiConsumer<String, Records> onData) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        //TODO: register onData listener

        return sendRequest(RequestType.subscribe, request);
    }

    @Override
    public CompletableFuture<OperationResult> unsubscribe(Session session, String subscriptionId) {
        Map<String, Object> request = new TreeMap<>();
        request.put("subscriptionId", subscriptionId);
        return sendRequest(RequestType.unsubscribe, request);
    }

    @Override
    public CompletableFuture<OperationResult> compute(Session session, String image, ComputeOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("image", image);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        return sendRequest(RequestType.compute, request);
    }

    @Override
    public CompletableFuture<OperationResult> flearn(Session session, String image, FLOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("image", image);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        return sendRequest(RequestType.f_learn, request);
    }

    @Override
    public CompletableFuture<OperationResult> splitLearn(Session session, String image, SplitLearnOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("image", image);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        return sendRequest(RequestType.split_learn, request);
    }

    @Override
    public CompletableFuture<OperationResult> heGetInputs(Session session, List<Object> datasources, List<Object> args) {
        Map<String, Object> request = new TreeMap<>();
        request.put("datasources", Utils.getGson().toJson(datasources));
        if (args != null) {
            request.put("args", Utils.getGson().toJson(args));
        }

        return sendRequest(RequestType.he_get_inputs, request);
    }

    @Override
    public CompletableFuture<OperationResult> heEncode(Session session, List<Object> items) {
        Map<String, Object> request = new TreeMap<>();
        request.put("items", Utils.getGson().toJson(items));

        return sendRequest(RequestType.he_encode, request);
    }

    @Override
    public CompletableFuture<OperationResult> pluginCall(Session session, String plugin, String request, Map<String, Object> args, int timeoutSec) {
        Map<String, Object> params = new TreeMap<>();
        params.put("organization", session.getOrganization());
        params.put("account", session.getAccount());
        params.put("request", request);
        params.put("plugin", plugin);
        params.put("args", args);

        return sendRequest(RequestType.plugin_call, params);
    }

    @Override
    public CompletableFuture<OperationResult> zkProof(Session session, String scope, String table, String gadget, String params, List<String> fields, Filter filter, ZKOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        request.put("gadget", gadget);
        request.put("params", params);
        request.put("fields", Utils.getGson().toJson(fields));
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.zk_proof, request);
    }

    @Override
    public CompletableFuture<OperationResult> zkDataProof(Session session, String gadget, String params, List<Object> values, ZKOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("gadget", gadget);
        request.put("params", params);
        request.put("values", Utils.getGson().toJson(values));
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.zk_data_proof, request);
    }


    @Override
    public CompletableFuture<OperationResult> proofsLastHash(Session session, String scope, String table) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        addAuthParams(request, session);
        return sendRequest(RequestType.proofs_last_hash, request);
    }

    @Override
    public CompletableFuture<OperationResult> updateProofs(Session session, String scope, String table) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        addAuthParams(request, session);
        return sendRequest(RequestType.update_proofs, request);
    }

    @Override
    public CompletableFuture<OperationResult> mpc(Session session, String scope, String table, String algo, List<String> fields, Filter filter, MPCOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        request.put("algo", algo);
        request.put("fields", Utils.getGson().toJson(fields));
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.mpc, request);
    }

    @Override
    public CompletableFuture<OperationResult> mpcInitProtocol(Session session, String computationId, int nodeIndex, String scope, String table, String algo, List<String> fields, Filter filter, Map<String, Integer> indexedPeers, MPCOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("computationId", computationId);
        request.put("nodeIndex", nodeIndex);
        request.put("scope", scope);
        request.put("table", table);
        request.put("algo", algo);
        request.put("indexedPeers", Utils.getGson().toJson(indexedPeers));
        request.put("fields", Utils.getGson().toJson(fields));
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.mpc_init, request);
    }

    @Override
    public CompletableFuture<OperationResult> mpcProtocol(Session session, String computationId, String message) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("computationId", computationId);
        request.put("message", message);
        addAuthParams(request, session);
        return sendRequest(RequestType.mpc_proto, request);
    }

    @Override
    public CompletableFuture<OperationResult> proxyEncryptSecret(Session session, String scope, String table, ProxyEncryptedData pre) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        request.put("pre", pre.toJson());
        addAuthParams(request, session);
        return sendRequest(RequestType.proxy_encrypt, request);
    }

    @Override
    public CompletableFuture<OperationResult> proxyReEncryptSecret(Session session, String scope, String table) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        addAuthParams(request, session);
        return sendRequest(RequestType.proxy_reencrypt, request);
    }

    @Override
    public CompletableFuture<OperationResult> blindSignature(Session session, String blinded) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("blinded", blinded);
        addAuthParams(request, session);
        return sendRequest(RequestType.blind_signature, request);
    }

    @Override
    public CompletableFuture<OperationResult> heGetOutputs(Session session, String encoded, List<Object> args) {
        Map<String, Object> request = new TreeMap<>();
        request.put("encoded", encoded);
        if (args != null) {
            request.put("args", Utils.getGson().toJson(args));
        }

        return sendRequest(RequestType.he_get_outputs, request);
    }

    @Override
    public CompletableFuture<OperationResult> storageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        request.put("challenge", challenge);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.storage_proof, request);
    }

    @Override
    public CompletableFuture<OperationResult> zkStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        request.put("challenge", challenge);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.zk_storage_proof, request);
    }

    @Override
    public CompletableFuture<OperationResult> merkleTree(Session session, String scope, String table, Filter filter, String salt, ReadOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        request.put("salt", salt);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.merkle_tree, request);
    }

    @Override
    public CompletableFuture<OperationResult> merkleProof(Session session, String scope, String table, String hash) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        request.put("hash", hash);
        addAuthParams(request, session);
        return sendRequest(RequestType.merkle_proof, request);
    }

    @Override
    public CompletableFuture<OperationResult> zkMerkleTree(Session session, String scope, String table, Filter filter, String salt, Integer rounds, Integer seed, ZKOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        request.put("rounds", rounds);
        request.put("seed", seed);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        request.put("salt", salt);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.zk_merkle_tree, request);
    }

    @Override
    public CompletableFuture<OperationResult> rootHash(Session session, String scope, String table) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);

        addAuthParams(request, session);
        return sendRequest(RequestType.root_hash, request);
    }

    @Override
    public CompletableFuture<OperationResult> verifyDataSignature(Session session, String signer, String signature, String data) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("signer", signer);
        request.put("signature", signature);
        request.put("data", data);

        addAuthParams(request, session);
        return sendRequest(RequestType.verify_data_signature, request);
    }

    @Override
    public CompletableFuture<OperationResult> taskLineage(Session session, String taskId) {
        Map<String, Object> request = new TreeMap<>();
        request.put("taskId", taskId);

        return sendRequest(RequestType.task_lineage, request);
    }

    @Override
    public CompletableFuture<OperationResult> hashCheckpoint(Session session) {
        return hashCheckpoint(session, null);
    }

    @Override
    public CompletableFuture<OperationResult> hashCheckpoint(Session session, Boolean enable) {
        Map<String, Object> request = new TreeMap<>();
        request.put("enable", enable);

        return sendRequest(RequestType.hash_checkpoint, request);
    }

    @Override
    public CompletableFuture<OperationResult> verifyTaskLineage(Session session, Map<String, Object> metadata) {
        Map<String, Object> request = new TreeMap<>();
        request.put("metadata", metadata);

        return sendRequest(RequestType.verify_task_lineage, request);
    }

    @Override
    public CompletableFuture<OperationResult> taskOutputData(Session session, String taskId, OutputOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("taskId", taskId);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        return sendRequest(RequestType.task_output_data, request);
    }

    @Override
    public CompletableFuture<OperationResult> history(Session session, String scope, String table, Filter filter, HistoryOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.history, request);
    }

    @Override
    public CompletableFuture<OperationResult> writers(Session session, String scope, String table, Filter filter) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.writers, request);
    }

    @Override
    public CompletableFuture<OperationResult> tasks(Session session, String scope, String table, Filter filter) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.tasks, request);
    }

    @Override
    public CompletableFuture<OperationResult> lineage(Session session, String scope, String table, Filter filter) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (filter != null) {
            request.put("filter", Utils.getGson().toJson(filter));
        }
        addAuthParams(request, session);
        return sendRequest(RequestType.lineage, request);
    }

    @Override
    public CompletableFuture<OperationResult> deployOracle(Session session, String oracleType, String targetBlockchain, String source, DeployOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("oracleType", oracleType);
        request.put("targetBlockchain", targetBlockchain);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        return sendRequest(RequestType.deploy_oracle, request);
    }

    @Override
    public CompletableFuture<OperationResult> postMessage(Session session, String targetInboxKey, String message, MessageOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("targetInboxKey", targetInboxKey);
        request.put("message", message);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        return sendRequest(RequestType.post_message, request);
    }

    @Override
    public CompletableFuture<OperationResult> pollMessages(Session session, String inboxKey, MessageOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("inboxKey", inboxKey);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        return sendRequest(RequestType.poll_messages, request);
    }

    @Override
    public CompletableFuture<OperationResult> deployFeed(Session session, String image, DeployOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("image", image);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        return sendRequest(RequestType.deploy_feed, request);
    }

    @Override
    public CompletableFuture<OperationResult> removeFeed(Session session, String feedId) {
        Map<String, Object> request = new TreeMap<>();
        request.put("feedId", feedId);

        return sendRequest(RequestType.remove_feed, request);
    }

    @Override
    public CompletableFuture<OperationResult> startFeed(Session session, String feedId, ComputeOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("feedId", feedId);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }

        return sendRequest(RequestType.start_feed, request);
    }

    @Override
    public CompletableFuture<OperationResult> stopFeed(Session session, String feedId) {
        Map<String, Object> request = new TreeMap<>();
        request.put("feedId", feedId);

        return sendRequest(RequestType.stop_feed, request);
    }

    @Override
    public CompletableFuture<OperationResult> broadcast(Session session, ConsensusMessage message) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("message", Utils.getMessageJsonAdapter().toJson(message));
        addAuthParams(request, session);
        return sendRequest(RequestType.broadcast, request);
    }

    private CompletableFuture<OperationResult> sendRequest(RequestType requestType, Map<String, Object> request) {
        CompletableFuture<OperationResult> future = new CompletableFuture<>();
        String requestID = Utils.generateUUID();
        request.put("id", requestID);

        String type = requestType.name();
        String feeLimits = getFeeLimits(requestType);
        if (feeLimits != null) {
            request.put("feeLimit", feeLimits);
        }

        //TODO: encodings
        byte[] cmd = Utils.getGson().toJson(request).getBytes(StandardCharsets.UTF_8);

        AMQP.BasicProperties props = null;

        pendingRequests.put(requestID, future);

        try {
            mainChannel.basicPublish("", type, props, cmd);
        } catch (IOException e) {
            logger.error("Failed message send", e);
            future.complete(null);
        }

        return future;
    }

    @Override
    public CompletableFuture<OperationResult> createAccount(Session session, String publicKey) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("publicKey", publicKey);
        return sendRequest(RequestType.create_account, request);
    }

    @Override
    public CompletableFuture<OperationResult> deploy(Session session, String contractType) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("contractType", contractType);
        return sendRequest(RequestType.deploy, request);
    }

    @Override
    public CompletableFuture<OperationResult> call(Session session, String contractAddress, String scope, String function, byte[] data) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("function", function);
        request.put("data", data);
        return sendRequest(RequestType.call, request);
    }

    @Override
    public CompletableFuture<OperationResult> balance(Session session, String accountAddress, String scope, String token) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("accountAddress", accountAddress);
        request.put("scope", scope);
        request.put("token", token);
        return sendRequest(RequestType.balance, request);
    }

    @Override
    public CompletableFuture<OperationResult> transfer(Session session, String accountAddress, String scope, String token, BigDecimal amount) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("accountAddress", accountAddress);
        request.put("scope", scope);
        request.put("token", token);
        request.put("amount", amount);
        return sendRequest(RequestType.transfer, request);
    }

    @Override
    public CompletableFuture<OperationResult> updateFees(Session session, String scope, String fees) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("fees", fees);
        return sendRequest(RequestType.update_fees, request);
    }


    @Override
    public CompletableFuture<OperationResult> contractState(Session session, String contractAddress, String scope) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("contractAddress", contractAddress);
        request.put("scope", scope);
        return sendRequest(RequestType.contract_state, request);
    }

    @Override
    public CompletableFuture<OperationResult> broadcastBlock(Session session, String scope, String block) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("block", block);
        return sendRequest(RequestType.broadcast_block, request);
    }

    @Override
    public CompletableFuture<OperationResult> broadcastChain(Session session, String scope, List<String> blocks) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("blocks", blocks);
        return sendRequest(RequestType.broadcast_chain, request);
    }

    @Override
    public CompletableFuture<OperationResult> forwardedRequest(Session session, Map<String, Object> msg) {
        Map<String, Object> request = new TreeMap<>(msg);
        return sendRequest(RequestType.forwarded_request, request);
    }

    @Override
    public CompletableFuture<OperationResult> getSidechainDetails(Session session) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        return sendRequest(RequestType.get_sidechain_details, request);
    }

    @Override
    public CompletableFuture<OperationResult> getNodes(Session session) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        return sendRequest(RequestType.get_nodes, request);
    }

    @Override
    public CompletableFuture<OperationResult> getScopes(Session session) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        return sendRequest(RequestType.get_scopes, request);
    }

    @Override
    public CompletableFuture<OperationResult> getTables(Session session, String scope) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        return sendRequest(RequestType.get_tables, request);
    }

    @Override
    public CompletableFuture<OperationResult> getTableDefinition(Session session, String scope, String table) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        return sendRequest(RequestType.get_table_definition, request);

    }

    @Override
    public CompletableFuture<OperationResult> getNodeConfig(Session session, String nodePublicKey) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("nodePublicKey", nodePublicKey);
        return sendRequest(RequestType.get_node_config, request);
    }

    @Override
    public CompletableFuture<OperationResult> getAccountNotifications(Session session) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        return sendRequest(RequestType.get_account_notifications, request);
    }

    @Override
    public CompletableFuture<OperationResult> updateConfig(Session session, String path, Map<String, Object> values) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("path", path);
        request.put("values", values);
        return sendRequest(RequestType.update_config, request);
    }

    @Override
    public CompletableFuture<OperationResult> grantRole(Session session, String account, Set<String> roles) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("targetAccount", account);
        request.put("roles", roles);
        return sendRequest(RequestType.grant_role, request);
    }

    @Override
    public CompletableFuture<OperationResult> createUserAccount(Session session, String targetOrganization, String newAccount, String publicKey, Set<String> roles, boolean isSuperAdmin) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("targetOrganization", targetOrganization);
        request.put("targetAccount", newAccount);
        request.put("publicKey", publicKey);
        request.put("roles", String.join(" ", roles));
        request.put("isSuperAdmin", isSuperAdmin ? 1 : 0);
        return sendRequest(RequestType.create_user_account, request);
    }

    @Override
    public CompletableFuture<OperationResult> resetConfig(Session session) {
        Map<String, Object> request = new TreeMap<>();
        addAuthParams(request, session);
        return sendRequest(RequestType.create_user_account, request);
    }

    @Override
    public CompletableFuture<OperationResult> withdraw(Session session, String token, BigInteger amount) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("amount", amount);
        return sendRequest(RequestType.withdraw, request);
    }

    @Override
    public CompletableFuture<OperationResult> withdrawAuthorize(Session session, String token, String address) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("address", address);
        return sendRequest(RequestType.withdraw_auth, request);
    }

    @Override
    public CompletableFuture<OperationResult> uploadApi(Session session, Map<String, Object> params) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        if (params != null) {
            request.put("params", Utils.getGson().toJson(params));
        }
        return sendRequest(RequestType.upload_api, request);
    }

    @Override
    public CompletableFuture<OperationResult> setThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        return sendRequest(RequestType.set_threshold_sig_pub_key, request);
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigPubkeyRound1(Session session, String scope, String table, String uuid, String message, ThresholdSigOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        request.put("hash", message);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        return sendRequest(RequestType.threshold_sig_pubkey_round_1, request);
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigRound2(Session session, String scope, String table, String uuid, String message, byte[] scalarK, ThresholdSigOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        request.put("uuid", uuid);
        request.put("hash", message);
        request.put("scalarK", Base58.encode(scalarK));
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        return sendRequest(RequestType.threshold_sig_round_2, request);
    }

    @Override
    public CompletableFuture<OperationResult> readThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("scope", scope);
        request.put("table", table);
        if (options != null) {
            request.put("options", Utils.getGson().toJson(options));
        }
        return sendRequest(RequestType.read_threshold_sig_pub_key, request);
    }

    @Override
    public CompletableFuture<OperationResult> issueCredentials(Session session, String issuer, String holder, Map<String, Object> credentials, CredentialsOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("issuer", issuer);
        request.put("holder", holder);
        request.put("credentials", credentials);
        return sendRequest(RequestType.issue_credentials, request);
    }

    @Override
    public CompletableFuture<OperationResult> verifyCredentials(Session session, Map<String, Object> credentials, CredentialsOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("credentials", credentials);
        return sendRequest(RequestType.verify_credentials, request);
    }

    @Override
    public CompletableFuture<OperationResult> createPresentation(Session session, Map<String, Object> credentials, String subject, CredentialsOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("credentials", credentials);
        request.put("subject", subject);
        request.put("options", options);
        return sendRequest(RequestType.create_presentation, request);
    }

    @Override
    public CompletableFuture<OperationResult> signPresentation(Session session, Map<String, Object> presentation, String domain, String challenge, CredentialsOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("presentation", presentation);
        request.put("domain", domain);
        request.put("challenge", challenge);
        request.put("options", options);
        return sendRequest(RequestType.sign_presentation, request);
    }

    @Override
    public CompletableFuture<OperationResult> verifyPresentation(Session session, Map<String, Object> signedPresentation, String domain, String challenge, CredentialsOptions options) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("presentation", signedPresentation);
        request.put("domain", domain);
        request.put("challenge", challenge);
        return sendRequest(RequestType.verify_presentation, request);
    }

    @Override
    public CompletableFuture<OperationResult> peerStatus(Session session, List<String> queuedReplies) {
        Map<String, Object> request = new TreeMap<>();
        request.put("organization", session.getOrganization());
        request.put("account", session.getAccount());
        request.put("passive_replies", queuedReplies);
        addAuthParams(request, session);
        return sendRequest(RequestType.peer_status, request);
    }
}
