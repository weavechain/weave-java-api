package com.weavechain.api.client.ws;

import com.weavechain.api.ApiContext;
import com.weavechain.api.auth.BLSKeyPair;
import com.weavechain.api.client.async.AsyncClient;
import com.weavechain.api.client.async.PendingRequest;
import com.weavechain.api.config.transport.WSClientConfig;
import com.weavechain.api.pre.ProxyEncryptedData;
import com.weavechain.api.session.Session;
import com.weavechain.core.batching.BatchData;
import com.weavechain.core.batching.BatchHelper;
import com.weavechain.core.batching.RecordBatchLocation;
import com.weavechain.core.consensus.ConsensusMessage;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.Records;
import com.weavechain.core.data.filter.Filter;
import com.weavechain.core.encoding.ContentEncoder;
import com.weavechain.core.encoding.Encoding;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.KeyExchange;
import com.weavechain.core.encrypt.KeysProvider;
import com.weavechain.core.error.AccessError;
import com.weavechain.core.error.Forward;
import com.weavechain.core.error.OperationResult;
import com.weavechain.core.error.OperationResultSerializer;
import com.weavechain.core.file.FileFormat;
import com.weavechain.core.operations.*;
import com.weavechain.core.requests.RequestType;
import com.weavechain.core.utils.CompletableFuture;
import org.apache.commons.codec.binary.Base64;
import org.bitcoinj.base.Base58;
import org.bouncycastle.util.encoders.Hex;
import org.java_websocket.exceptions.WebsocketNotConnectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;

public class WSApiClient extends AsyncClient {

    static final Logger logger = LoggerFactory.getLogger(WSApiClient.class);

    private final WSClientConfig config;

    private WSClient wsClient;

    private final BatchHelper batchHelper = new BatchHelper();

    private final ContentEncoder contentEncoder = Encoding.getDefaultContentEncoder();

    private static final int RETRIES = 30;

    private final Map<String, CompletableFuture<OperationResult>> pendingRequests = Utils.newConcurrentHashMap();

    private final Map<String, BiConsumer<String, Records>> registeredListeners = Utils.newConcurrentHashMap();
    private final Map<String, DataLayout> tableLayouts = Utils.newConcurrentHashMap();

    private BiConsumer<WSClient, String> onRemoteRequestListener;

    public WSApiClient(WSClientConfig config, ApiContext apiContext) {
        super(apiContext);
        this.config = config.copy();
    }

    private String getApiURL() {
        return String.format("%s://%s:%s",
                config.isUseWss() ? "wss" : "ws",
                Utils.parseHost(config.getHost()),
                config.getPort()
        );
    }

    private void connectAsync() {
        Thread connectThread = new Thread(this::connect);
        connectThread.setDaemon(true);
        connectThread.start();
    }

    private void connect() {
        String uri = getApiURL();

        try {
            int cnt = 0;
            while (cnt < config.getConnectRetryCount()) {
                wsClient = new WSClient(new URI(uri), this);
                if (config.isUseWss()) {
                    initSSL(config);
                }

                if (wsClient.connectBlocking()) {
                    break;
                }
                cnt++;
                Thread.sleep(config.getConnectRetrySec() * 1000);
            }
        } catch (Exception e) {
            wsClient = null;
            logger.error("Failed connecting WS client", e);
        }
    }

    private void initSSL(WSClientConfig config) {
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

            wsClient.setSocketFactory(socketFactory);
        } catch (Throwable e) {
            logger.error("Failed initializing SSL", e);
        }
    }

    @Override
    public boolean init() {
        try {
            Thread.sleep(200);
            connect();

            keysInit();

            return true;
        } catch (Exception e) {
            logger.error("Could not retrieve server public key", e);
            return false;
        }
    }

    protected void addPendingRequest(PendingRequest pending, String requestID) {
        pendingRequests.put(requestID, pending.getResult());
    }

    protected void sendRequest(String id, PendingRequest req, boolean isAuthenticated) {
        if (wsClient != null) {
            if (req.getMessage() != null) {
                int nTry = 0;
                while (nTry < RETRIES) {
                    try {
                        if (config.isEncrypted() && isAuthenticated) {
                            byte[] iv = KeysProvider.generateIV();
                            KeyExchange keyExchange = KeysProvider.getInstance();
                            SecretKey secretKey = keyExchange.sharedSecret(getApiContext().getClientPrivateKey(), getApiContext().getServerPublicKey(), null);
                            byte[] encrypted = keyExchange.encrypt(secretKey, req.getMessage().getBytes(StandardCharsets.UTF_8), getApiContext().getSeed(), iv);


                            Map<String, Object> encParams = new HashMap<>();
                            encParams.put("id", id);
                            encParams.put("type", RequestType.enc.name());
                            encParams.put("x-enc", Base64.encodeBase64String(encrypted));
                            encParams.put("x-iv", Hex.toHexString(iv));
                            encParams.put("x-key", getApiContext().getPublicKey());

                            wsClient.send(Utils.getGson().toJson(encParams));
                        } else {
                            wsClient.send(req.getMessage());
                        }
                        break;
                    } catch (WebsocketNotConnectedException e) {
                        logger.error("Websocket not connected", e);
                        nTry++;
                        if (nTry < RETRIES) {
                            //TODO: smarter reconnect, nicer code, extending timeout with each failure
                            connect();
                        }
                    }
                }
            } else {
                logger.error("Null message");
            }
        } else {
            logger.error("WS client down");
        }
    }

    public void onOpen() {
    }

    @SuppressWarnings("unchecked")
    public void onMessage(String message) {
        try {
            Map<String, Object> msg = Utils.getGson().fromJson(message, Map.class);

            String id = (String) msg.get("id");
            OperationResult reply = OperationResultSerializer.from(msg.get("reply"));
            String error = (String) msg.get("error");

            if (reply instanceof Forward) {
                String decryptedResult = decryptProxyParams(reply);
                reply = decryptedResult != null ? OperationResultSerializer.from(decryptedResult) : reply;
            }

            CompletableFuture<OperationResult> request = id != null ? pendingRequests.remove(id) : null;
            if (request != null) {
                if (error != null) {
                    logger.error("Error: " + error);
                }

                request.complete(reply);
            } else if (msg.get("event_id") != null) {
                String subscriptionId = ConvertUtils.convertToString(msg.get("sub_id"));
                BiConsumer<String, Records> onData = registeredListeners.get(subscriptionId);
                if (onData != null) {
                    DataLayout layout = tableLayouts.get(subscriptionId);
                    Records records = contentEncoder.decode(
                            ConvertUtils.convertToString(reply.getData()),
                            layout != null ? layout : DataLayout.DEFAULT
                    );
                    onData.accept(subscriptionId, records);
                } else {
                    logger.warn("Ignoring event for inexistent subscription " + subscriptionId);
                }
            } else {
                if (onRemoteRequestListener != null) {
                    onRemoteRequestListener.accept(wsClient, message);
                } else {
                    logger.warn("Ignoring reply for inexistent request " + id);
                }
            }

        } catch (Exception e) {
            logger.error("Failed parsing message", e);
        }
    }

    public void registerRemoteRequestListener(BiConsumer<WSClient, String> onRemoteRequest) {
        this.onRemoteRequestListener = onRemoteRequest;
    }

    public void onClose(int code, String reason, boolean remote) {
    }

    public void onError(Exception e) {
        logger.error("Websocket error", e);
    }

    @Override
    public CompletableFuture<OperationResult> version() {
        Map<String, Object> request = new HashMap<>();
        RequestType requestType = RequestType.version;

        return sendRequest(requestType, request, false, null, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> ping() {
        Map<String, Object> request = new HashMap<>();
        RequestType requestType = RequestType.ping;
        return sendRequest(requestType, request, false, null, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> publicKey() {
        Map<String, Object> request = new HashMap<>();
        RequestType requestType = RequestType.public_key;
        return sendRequest(requestType, request, false, null, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> sigKey() {
        return sigKey(null);
    }

    @Override
    public CompletableFuture<OperationResult> sigKey(String account) {
        Map<String, Object> request = new HashMap<>();
        RequestType requestType = RequestType.sig_key;
        if (account != null) {
            request.put("account", account);
        }
        return sendRequest(requestType, request, false, null, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> rsaKey() {
        return rsaKey(null);
    }

    @Override
    public CompletableFuture<OperationResult> rsaKey(String account) {
        Map<String, Object> request = new HashMap<>();
        RequestType requestType = RequestType.rsa_key;
        if (account != null) {
            request.put("account", account);
        }
        return sendRequest(requestType, request, false, null, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> blsKey() {
        return blsKey(null);
    }

    @Override
    public CompletableFuture<OperationResult> blsKey(String account) {
        Map<String, Object> request = new HashMap<>();
        RequestType requestType = RequestType.bls_key;
        if (account != null) {
            request.put("account", account);
        }
        return sendRequest(requestType, request, false, null, null, null);
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes) {
        return login(organization, account, scopes, null);
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes, String credentials) {
        CompletableFuture<Session> sess = new CompletableFuture<>();

        try {
            String toSign = organization + "\n" + getClientPublicKey() + "\n" + scopes;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);

            Map<String, Object> request = new HashMap<>();
            RequestType requestType = RequestType.login;
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

            sendRequest(requestType, request, false, null, null, null).whenComplete((data, e) -> {
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
        } catch (Exception e) {
            logger.error("Failed login", e);
            sess.complete(null);
            return sess;
        }
    }

    @Override
    public CompletableFuture<Session> proxyLogin(String node, String organization, String account, String scopes) {
        CompletableFuture<Session> sess = new CompletableFuture<>();

        try {
            Map<String, Object> request = buildProxyLoginParams(node, organization, account, scopes);

            sendRequest(RequestType.proxy_login, request, false, null, null, null).whenComplete((data, e) -> {
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
        } catch (Exception e) {
            logger.error("Failed login", e);
            sess.complete(null);
            return sess;
        }
    }

    @Override
    public CompletableFuture<OperationResult> logout(Session session) {
        try {
            Map<String, Object> request = new TreeMap<>(); //order is important for signing
            RequestType requestType = RequestType.logout;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed logout", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> terms(Session session, TermsOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>(); //order is important for signing
            RequestType requestType = RequestType.terms;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            String termsOptions = Utils.getGson().toJson(options);
            request.put("options", termsOptions);
            request.put("signature", sign(termsOptions));
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed terms", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> status(Session session) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.status;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed status", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> createTable(Session session, String scope, String table, CreateOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.create;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            return sendRequest(requestType, request, true, session, null, options != null ? options.getCreateTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed create", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> dropTable(Session session, String scope, String table, DropOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.drop;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            return sendRequest(requestType, request, true, session, null, options != null ? options.getDropTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed create", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> updateLayout(Session session, String scope, String table, String layout) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.update_layout;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            request.put("layout", layout);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed create", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> write(Session session, String scope, Records records, WriteOptions options) {
        if (options.isAllowLocalBatching()) {
            RecordBatchLocation location = new RecordBatchLocation(session.getAccount(), session.getOrganization(), scope, records.getTable(), options);

            final BatchData currentBatch = batchHelper.getBatch(location, options.getWriteTimeoutSec() + options.getBatchingOptions().getWaitTimeMs());
            currentBatch.addRecord(records);

            batchHelper.checkBatch(currentBatch, options.getBatchingOptions(), () -> doBatchWrite(session, currentBatch, options, currentBatch.getResult()));

            //TODO: clarify if ok to return the batch future multiple times or we should handle this in 2 stages, return first Pending then the actual result
            return currentBatch.getResult();
        } else {
            return doWrite(session, scope, records, options);
        }
    }

    public void doBatchWrite(
            Session session,
            BatchData batch,
            WriteOptions options,
            CompletableFuture<OperationResult> opResult
    ) {
        try {
            if (batch.getDispatched().compareAndSet(false, true)
                    && batchHelper.timeTillReady(batch, options.getBatchingOptions()) == 0) {
                Records records = new Records(batch.getLocation().getTable(), new ArrayList<>(), null, null);
                records.setIntegrity(new CopyOnWriteArrayList<>());
                batch.addItemsTo(records);

                CompletableFuture<OperationResult> writeResult = doWrite(session, batch.getLocation().getScope(), records, batch.getLocation().getWriteOptions());
                writeResult.whenComplete((result, ex) -> {
                    if (ex != null) {
                        opResult.complete(new AccessError(null, ex.toString()));
                    } else {
                        opResult.complete(result);
                    }
                });
            }
        } catch (Exception e) {
            logger.error("Failed write", e);
            opResult.complete(new AccessError(null, e.toString()));
        }
    }

    public CompletableFuture<OperationResult> doWrite(Session session, String scope, Records records, WriteOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.write;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", records.getTable());

            addIntegritySignatureIfConfigured(records, session, scope, request);

            Runnable delayedPrepare = null;
            if (records.getSerialization() != null) {
                request.put("records", records.getSerialization());
                if (records.getEncoding() != null) {
                    request.put("enc", records.getEncoding());
                }
                if (options != null) {
                    request.put("options", Utils.getWriteOptionsJsonAdapter().toJson(options));
                }
            } else if (options.isAllowLocalBatching()) {
                //TODO: maybe add a different condition here.
                //  Using isAllowLocalBatching as peer replication has it false and if we have serialization deferred on another thread it hurts performance when server replicates because of records structures leak
                //  Given that it took such a long comment to describe the issue it means we need a refactor here
                delayedPrepare = () -> addWriteSerializations(session, request, scope, records, options);
            } else {
                addWriteSerializations(session, request, scope, records, options);
            }

            return sendRequest(requestType, request, true, session, delayedPrepare, options != null ? options.getWriteTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed write", e);
            return failure(e);
        }
    }

    private void addWriteSerializations(Session session, Map<String, Object> request, String scope, Records records, WriteOptions options) {
        DataLayout layout = getTableLayout(session, scope, records.getTable());

        ContentEncoder encoder = layout != null ? contentEncoder : Encoding.getJsonContentEncoder();
        if (encoder != Encoding.getDefaultContentEncoder()) {
            request.put("enc", encoder.getType());
        }

        String serializedRecords = encoder.encode(records, layout);
        request.put("records", serializedRecords);
        if (options != null) {
            request.put("options", Utils.getWriteOptionsJsonAdapter().toJson(options));
        }
    }

    @Override
    public CompletableFuture<OperationResult> read(Session session, String scope, String table, Filter filter, ReadOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.read;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed read", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> count(Session session, String scope, String table, Filter filter, ReadOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.count;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed count", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> delete(Session session, String scope, String table, Filter filter, DeleteOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            if (filter != null) {
                request.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                DeleteOptions optionsCopy = options.copy();
                optionsCopy.setContext(null);
                request.put("options", Utils.getGson().toJson(optionsCopy));
            }
            return sendRequest(RequestType.delete, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed delete", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> hashes(Session session, String scope, String table, Filter filter, ReadOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.hashes;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed reading hashes", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> downloadTable(Session session, String scope, String table, Filter filter, FileFormat format, ReadOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.download_table;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed download", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> downloadDataset(Session session, String did, ReadOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.download_dataset;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("did", did);
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed download", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> publishDataset(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String scope, String table, Filter filter, FileFormat format, BigDecimal price, String token, Long pageorder, PublishDatasetOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.publish_dataset;
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
            request.put("price", price != null ? price.toString() : null);
            request.put("token", token);
            request.put("pageorder", pageorder);
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed publish", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> enableProduct(Session session, String did, String productType, Boolean active) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.enable_product;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("did", did);
            request.put("productType", productType);
            request.put("active", active);

            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed enable product", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> runTask(Session session, String did, ComputeOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.run_task;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("did", did);
            return sendRequest(requestType, request, true, session, null, options != null ? options.getTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed task run", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> publishTask(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String task, BigDecimal price, String token, Long pageorder, PublishTaskOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.publish_task;
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
            request.put("price", price != null ? price.toString() : null);
            request.put("token", token);
            request.put("pageorder", pageorder);
            return sendRequest(requestType, request, true, session, null, options != null ? options.getComputeTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed publish", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> subscribe(Session session, String scope, String table, Filter filter, SubscribeOptions options, BiConsumer<String, Records> onData) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.subscribe;
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

            CompletableFuture<OperationResult> future = sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
            future.whenComplete((r, ex) -> {
                if (ex == null) {
                    String subscriptionId = r.getData() != null ? r.getData().toString() : null;
                    DataLayout layout = getTableLayout(session, scope, table);
                    tableLayouts.put(subscriptionId, layout);
                    registeredListeners.put(subscriptionId, onData);
                }
            });
            return future;
        } catch (Exception e) {
            logger.error("Failed subscribe", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> unsubscribe(Session session, String subscriptionId) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.unsubscribe;
            request.put("subscriptionId", subscriptionId);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed unsubscribe", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> compute(Session session, String image, ComputeOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.compute;
            request.put("image", image);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            return sendRequest(requestType, request, true, session, null, options != null ? options.getTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> flearn(Session session, String image, FLOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.f_learn;
            request.put("image", image);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            return sendRequest(requestType, request, true, session, null, options != null ? options.getTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed federated learning", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> splitLearn(Session session, String image, SplitLearnOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.split_learn;
            request.put("image", image);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            return sendRequest(requestType, request, true, session, null, options != null ? options.getTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed split learning", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> heGetInputs(Session session, List<Object> datasources, List<Object> args) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.he_get_inputs;
            request.put("datasources", Utils.getGson().toJson(datasources));
            if (args != null) {
                request.put("args", Utils.getGson().toJson(args));
            }
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed HE get inputs", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> heGetOutputs(Session session, String encoded, List<Object> args) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.he_get_outputs;
            request.put("encoded", encoded);
            if (args != null) {
                request.put("args", Utils.getGson().toJson(args));
            }
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed HE get outputs", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> heEncode(Session session, List<Object> items) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.he_encode;
            request.put("items", Utils.getGson().toJson(items));
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed HE encode", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> pluginCall(Session session, String plugin, String request, Map<String, Object> args, int timeoutSec) {
        try {
            Map<String, Object> params = new TreeMap<>();
            RequestType requestType = RequestType.plugin_call;
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("request", request);
            params.put("plugin", plugin);
            params.put("args", args);
            return sendRequest(requestType, params, true, session, null, timeoutSec);
        } catch (Exception e) {
            logger.error("Failed plugin call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> zkProof(Session session, String scope, String table, String gadget, String params, List<String> fields, Filter filter, ZKOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.zk_proof;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed generating proof", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> zkDataProof(Session session, String gadget, String params, List<Object> values, ZKOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.zk_data_proof;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("gadget", gadget);
            request.put("params", params);
            request.put("values", Utils.getGson().toJson(values));
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed generating proof", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> proofsLastHash(Session session, String scope, String table) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.proofs_last_hash;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);

            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed retrieving hash", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> updateProofs(Session session, String scope, String table) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.update_proofs;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed reading proofs", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> mpc(Session session, String scope, String table, String algo, List<String> fields, Filter filter, MPCOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.mpc;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed MPC", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> mpcInitProtocol(Session session, String computationId, int nodeIndex, String scope, String table, String algo, List<String> fields, Filter filter, Map<String, Integer> indexedPeers, MPCOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.mpc_init;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed MPC protocol init", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> mpcProtocol(Session session, String computationId, String message) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.mpc_proto;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("computationId", computationId);
            request.put("message", message);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed MPC protocol call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> proxyEncryptSecret(Session session, String scope, String table, ProxyEncryptedData pre) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.proxy_encrypt;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            request.put("pre", pre.toJson());
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed proxy encrypt call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> proxyReEncryptSecret(Session session, String scope, String table) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.proxy_reencrypt;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed proxy reencrypt call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> blindSignature(Session session, String blinded) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.blind_signature;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("blinded", blinded);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed blind signature call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> storageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.storage_proof;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed storage proof", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> zkStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.zk_storage_proof;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed storage proof", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> merkleTree(Session session, String scope, String table, Filter filter, String salt, ReadOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.merkle_tree;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed merkle tree call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> merkleProof(Session session, String scope, String table, String hash) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.merkle_proof;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            request.put("hash", hash);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed merkle proof call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> zkMerkleTree(Session session, String scope, String table, Filter filter, String salt, Integer rounds, Integer seed, ZKOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.zk_merkle_tree;
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
            return sendRequest(requestType, request, true, session, null, options != null ? options.getReadTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed zk merkle tree call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> rootHash(Session session, String scope, String table) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.root_hash;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed root hash call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> verifyDataSignature(Session session, String signer, String signature, String data) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.verify_data_signature;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("signer", signer);
            request.put("signature", signature);
            request.put("data", data);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed verify data signature call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> taskLineage(Session session, String taskId) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.task_lineage;
            request.put("taskId", taskId);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed task lineage", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> hashCheckpoint(Session session, Boolean enable) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.hash_checkpoint;
            request.put("enable", enable);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed hash checkpoint", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> verifyTaskLineage(Session session, Map<String, Object> metadata) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.verify_task_lineage;
            request.put("metadata", metadata);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed verify task lineage", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> taskOutputData(Session session, String taskId, OutputOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.task_output_data;
            request.put("taskId", taskId);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }

            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed task output data", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> history(Session session, String scope, String table, Filter filter, HistoryOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.history;
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
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed history call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> writers(Session session, String scope, String table, Filter filter) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.writers;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            if (filter != null) {
                request.put("filter", Utils.getGson().toJson(filter));
            }
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed writers call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> tasks(Session session, String scope, String table, Filter filter) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.tasks;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            if (filter != null) {
                request.put("filter", Utils.getGson().toJson(filter));
            }
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed writer-tasks call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> lineage(Session session, String scope, String table, Filter filter) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.lineage;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            if (filter != null) {
                request.put("filter", Utils.getGson().toJson(filter));
            }
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed lineage call", e);
            return failure(e);
        }
    }


    @Override
    public CompletableFuture<OperationResult> deployOracle(Session session, String oracleType, String targetBlockchain, String source, DeployOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.deploy_oracle;
            request.put("oracleType", oracleType);
            request.put("targetBlockchain", targetBlockchain);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }

            return sendRequest(requestType, request, true, session, null, options != null ? options.getTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed oracle deploy", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> postMessage(Session session, String targetInboxKey, String message, MessageOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.post_message;
            request.put("targetInboxKey", targetInboxKey);
            request.put("message", message);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }

            return sendRequest(requestType, request, true, session, null, options != null ? options.getOpTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed post message", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> pollMessages(Session session, String inboxKey, MessageOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.poll_messages;
            request.put("inboxKey", inboxKey);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }

            return sendRequest(requestType, request, true, session, null, options != null ? options.getOpTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed poll messages", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> deployFeed(Session session, String image, DeployOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.deploy_feed;
            request.put("image", image);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }

            return sendRequest(requestType, request, true, session, null, options != null ? options.getTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed deploy feed", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> removeFeed(Session session, String feedId) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.remove_feed;
            request.put("feedId", feedId);

            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed remove feed", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> startFeed(Session session, String feedId, ComputeOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.start_feed;
            request.put("feedId", feedId);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }

            return sendRequest(requestType, request, true, session, null, options != null ? options.getTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed start feed", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> stopFeed(Session session, String feedId) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.stop_feed;
            request.put("feedId", feedId);

            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed stop feed", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> broadcast(Session session, ConsensusMessage message) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.broadcast;
            request.put("msgtype", message.getType().name());
            request.put("organization", message.getOrganization());
            request.put("account", message.getAccount());
            request.put("scope", message.getScope());
            request.put("table", message.getTable());
            request.put("seqNum", message.getSeqNum());
            request.put("signerId", message.getSignerId());
            request.put("hash", message.getHash());
            request.put("viewId", message.getViewId());
            request.put("blockId", message.getBlockId());
            request.put("action", message.getAction());
            request.put("data", Utils.getMapJsonAdapter().toJson(message.getData()));
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed broadcast", e);
            return failure(e);
        }
    }

    private CompletableFuture<OperationResult> failure(Exception e) {
        CompletableFuture<OperationResult> op = new CompletableFuture<>();
        op.complete(new AccessError(null, e.toString()));
        return op;
    }

    @Override
    public CompletableFuture<OperationResult> createAccount(Session session, String publicKey) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.create_account;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("publicKey", publicKey);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed create account", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> deploy(Session session, String contractType) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.deploy;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("contractType", contractType);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed deploy", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> call(Session session, String contractAddress, String scope, String function, byte[] data) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.call;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("contractAddress", contractAddress);
            request.put("scope", scope);
            request.put("function", function);

            String encodedData = Base64.encodeBase64String(data);
            request.put("data", encodedData);

            String toSign = session.getOrganization()
                    + "\n" + getClientPublicKey()
                    + "\n" + contractAddress
                    + "\n" + scope
                    + "\n" + function
                    + "\n" + encodedData;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);
            request.put("signature", signature);
            request.put("x-iv", Hex.toHexString(iv));

            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed call", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> balance(Session session, String accountAddress, String scope, String token) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.balance;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("accountAddress", accountAddress);
            request.put("scope", scope);
            request.put("token", token);

            String toSign = session.getOrganization()
                    + "\n" + getClientPublicKey()
                    + "\n" + accountAddress
                    + "\n" + scope
                    + "\n" + token;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);
            request.put("signature", signature);
            request.put("x-iv", Hex.toHexString(iv));

            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed balance", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> transfer(Session session, String accountAddress, String scope, String token, BigDecimal amount) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.transfer;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("accountAddress", accountAddress);
            request.put("scope", scope);
            request.put("token", token);
            request.put("amount", amount.toString());

            String toSign = session.getOrganization()
                    + "\n" + getClientPublicKey()
                    + "\n" + accountAddress
                    + "\n" + scope
                    + "\n" + token
                    + "\n" + amount;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);
            request.put("signature", signature);
            request.put("x-iv", Hex.toHexString(iv));

            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed transfer", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> updateFees(Session session, String scope, String fees) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.update_fees;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("fees", fees);

            String toSign = session.getOrganization()
                    + "\n" + getClientPublicKey()
                    + "\n" + scope
                    + "\n" + fees;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);
            request.put("signature", signature);
            request.put("x-iv", Hex.toHexString(iv));

            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed update fees", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> contractState(Session session, String contractAddress, String scope) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.contract_state;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("contractAddress", contractAddress);
            request.put("scope", scope);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed retrieving contract state", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> broadcastBlock(Session session, String scope, String block) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.broadcast_block;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("block", block);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed block broadcast", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> broadcastChain(Session session, String scope, List<String> blocks) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.broadcast_chain;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("blocks", blocks);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed chain broadcast", e);
            return failure(e);
        }
    }

    protected CompletableFuture<OperationResult> getAdminData(Session session, RequestType requestType, String scope, String table) {
        try {
            Map<String, Object> request = new TreeMap<>();
            request.put("account", session.getAccount());
            if (scope != null) {
                request.put("scope", scope);
            }
            if (table != null) {
                request.put("table", table);
            }
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed get admin data", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> forwardedRequest(Session session, Map<String, Object> msg) {
        try {
            Map<String, Object> request = new TreeMap<>(msg);
            RequestType requestType = RequestType.forwarded_request;

            CompletableFuture<OperationResult> reply = new CompletableFuture<>();
            sendRequest(requestType, request, true, session, null, null).whenComplete((data, e) -> {
                if (e != null) {
                    logger.error("Failed login", e);
                    reply.complete(null);
                } else {
                    try {
                        reply.complete(data);
                    } catch (Exception ex) {
                        reply.complete(null);
                    }
                }
            });

            return reply;
        } catch (Exception e) {
            logger.error("Failed forwarding request", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> getSidechainDetails(Session session) {
        return getAdminData(session, RequestType.get_sidechain_details, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> getNodes(Session session) {
        return getAdminData(session, RequestType.get_nodes, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> getScopes(Session session) {
        return getAdminData(session, RequestType.get_scopes, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> getTables(Session session, String scope) {
        return getAdminData(session, RequestType.get_tables, scope, null);
    }

    @Override
    public CompletableFuture<OperationResult> getTableDefinition(Session session, String scope, String table) {
        return getAdminData(session, RequestType.get_table_definition, scope, table);
    }

    @Override
    public CompletableFuture<OperationResult> getNodeConfig(Session session, String nodePublicKey) {
        return getAdminData(session, RequestType.get_node_config, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> getAccountNotifications(Session session) {
        return getAdminData(session, RequestType.get_account_notifications, null, null);
    }

    @Override
    public CompletableFuture<OperationResult> updateConfig(Session session, String path, Map<String, Object> values) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.update_config;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("path", path);
            request.put("values", values);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed update config", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> grantRole(Session session, String account, Set<String> roles) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.grant_role;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("targetAccount", account);
            request.put("roles", roles);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed grant role", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> createUserAccount(Session session, String targetOrganization, String newAccount, String publicKey, Set<String> roles, boolean isSuperAdmin) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.create_user_account;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("targetOrganization", targetOrganization);
            request.put("targetAccount", newAccount);
            request.put("publicKey", publicKey);
            request.put("roles", String.join(" ", roles));
            request.put("isSuperAdmin", isSuperAdmin ? 1 : 0);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed update config", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> resetConfig(Session session) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.reset_config;
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed reset config", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> withdraw(Session session, String token, BigInteger amount) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.withdraw;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("amount", amount);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed withdraw", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> withdrawAuthorize(Session session, String token, String address) {
        try {
            String toSign = token + "\n" + address;
            String signature = KeysProvider.createAccountSignature(getApiContext().getSigPrivateKey(), toSign.getBytes(StandardCharsets.UTF_8));

            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.withdraw_auth;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("address", address);
            request.put("signature", signature);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed withdraw authorize", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> uploadApi(Session session, Map<String, Object> params) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.upload_api;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            if (params != null) {
                request.put("params", Utils.getGson().toJson(params));
            }
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed retrieving upload API token", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> setThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.set_threshold_sig_pub_key;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            logger.debug("Sending set threshold sig pub key request");
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed set threshold sig pub key", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigPubkeyRound1(Session session, String scope, String table, String uuid, String message, ThresholdSigOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.threshold_sig_pubkey_round_1;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            request.put("uuid", uuid);
            request.put("message", message);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            logger.debug("Sending threshold sig round 1 request");
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed threshold sig round 1", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigRound2(Session session, String scope, String table, String uuid, String message, byte[] scalarK, ThresholdSigOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.threshold_sig_round_2;
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
            logger.debug("Sending threshold sig round 2 request");
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed threshold sig round 2", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> readThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.read_threshold_sig_pub_key;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            logger.debug("Sending read threshold sig pub key request");
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed read threshold sig pub key", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> issueCredentials(Session session, String issuer, String holder, Map<String, Object> credentials, CredentialsOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.issue_credentials;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("issuer", issuer);
            request.put("holder", holder);
            request.put("credentials", credentials);
            request.put("options", options);
            return sendRequest(requestType, request, true, session, null, options != null ? options.getOpTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed credentials issue", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> verifyCredentials(Session session, Map<String, Object> credentials, CredentialsOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.verify_credentials;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("credentials", credentials);
            request.put("options", options);
            return sendRequest(requestType, request, true, session, null, options != null ? options.getOpTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed verify credentials", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> createPresentation(Session session, Map<String, Object> credentials, String subject, CredentialsOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.create_presentation;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("credentials", credentials);
            request.put("subject", subject);
            request.put("options", options);
            return sendRequest(requestType, request, true, session, null, options != null ? options.getOpTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed create presentation", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> signPresentation(Session session, Map<String, Object> presentation, String domain, String challenge, CredentialsOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.sign_presentation;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("presentation", presentation);
            request.put("domain", domain);
            request.put("challenge", challenge);
            request.put("options", options);
            return sendRequest(requestType, request, true, session, null, options != null ? options.getOpTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed presentation signing", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> verifyPresentation(Session session, Map<String, Object> signedPresentation, String domain, String challenge, CredentialsOptions options) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.verify_presentation;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("presentation", signedPresentation);
            request.put("domain", domain);
            request.put("challenge", challenge);
            request.put("options", options);
            return sendRequest(requestType, request, true, session, null, options != null ? options.getOpTimeoutSec() : null);
        } catch (Exception e) {
            logger.error("Failed presentation verify", e);
            return failure(e);
        }
    }

    @Override
    public CompletableFuture<OperationResult> peerStatus(Session session, List<String> queuedReplies) {
        try {
            Map<String, Object> request = new TreeMap<>();
            RequestType requestType = RequestType.peer_status;
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("passive_replies", queuedReplies);
            return sendRequest(requestType, request, true, session, null, null);
        } catch (Exception e) {
            logger.error("Failed status", e);
            return failure(e);
        }
    }
}
