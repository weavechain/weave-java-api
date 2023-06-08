package com.weavechain.api.client.http;

import com.weavechain.api.ApiContext;
import com.weavechain.api.auth.BLSKeyPair;
import com.weavechain.api.client.WeaveApiClientV1;
import com.weavechain.api.config.transport.HttpClientConfig;
import com.weavechain.api.pre.ProxyEncryptedData;
import com.weavechain.api.session.Session;
import com.weavechain.core.batching.BatchData;
import com.weavechain.core.batching.BatchHelper;
import com.weavechain.core.batching.RecordBatchLocation;
import com.weavechain.core.consensus.ConsensusMessage;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.Records;
import com.weavechain.core.data.filter.Filter;
import com.weavechain.core.encoding.ContentEncoder;
import com.weavechain.core.encoding.Encoding;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.Hash;
import com.weavechain.core.encrypt.KeyExchange;
import com.weavechain.core.encrypt.KeysProvider;
import com.weavechain.core.error.*;
import com.weavechain.core.file.FileFormat;
import com.weavechain.core.operations.*;
import com.weavechain.core.requests.RequestType;
import com.weavechain.core.utils.CompletableFuture;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.bitcoinj.base.Base58;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public class HttpApiClient extends WeaveApiClientV1 {

    static final Logger logger = LoggerFactory.getLogger(HttpApiClient.class);

    public static final String AUTH_HEADER = "x-wev-auth";

    private static final int DOWNLOAD_BUFFER_SIZE = 1024 * 1024;

    private final HttpClientConfig config;

    private final String apiUrl;

    private final BatchHelper batchHelper = new BatchHelper();

    private final ContentEncoder contentEncoder = Encoding.getDefaultContentEncoder();

    private final HttpTransport httpTransport;

    ThreadLocal<MessageDigest> replyDigest = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            return null;
        }
    });

    public HttpApiClient(HttpClientConfig config, ApiContext apiContext) {
        super(apiContext);
        this.config = config.copy();
        this.apiUrl = getApiURL();

        this.httpTransport = new HttpTransport(config);
    }

    private String getApiURL() {
        return String.format("%s://%s:%s",
                config.isUseHttps() ? "https" : "http",
                Utils.parseHost(config.getHost()),
                config.getPort()
        );
    }

    @Override
    public boolean init() {
        try {
            keysInit();

            return true;
        } catch (Exception e) {
            logger.error("Could not retrieve server public key", e);
            return false;
        }
    }

    private static OperationResult buildOperationResult(HttpReply reply) {
        return reply != null ? OperationResultSerializer.from(reply.getBody()) : new AccessError(null, "Request failed");
    }

    public OperationResult syncVersion() {
        String url = apiUrl + "/" + RequestType.version.name();
        HttpReply reply = httpTransport.syncGet(url);
        return buildOperationResult(reply);
    }

    @Override
    public CompletableFuture<OperationResult> version() {
        return asyncCall(this::syncVersion);
    }

    public OperationResult syncPing() {
        String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.ping.name();
        HttpReply reply = httpTransport.syncGet(url);
        return buildOperationResult(reply);
    }

    @Override
    public CompletableFuture<OperationResult> ping() {
        return asyncCall(this::syncPing);
    }

    public OperationResult syncPublicKey() {
        String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.public_key.name();
        HttpReply reply = httpTransport.syncGet(url);
        return buildOperationResult(reply);
    }

    @Override
    public CompletableFuture<OperationResult> publicKey() {
        return asyncCall(this::syncPublicKey);
    }

    public OperationResult syncSigKey() {
        String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.sig_key.name();
        HttpReply reply = httpTransport.syncGet(url);
        return buildOperationResult(reply);
    }

    @Override
    public CompletableFuture<OperationResult> sigKey() {
        return asyncCall(this::syncSigKey);
    }

    public OperationResult syncPostSigKey(String account) {
        String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.sig_key.name();
        Map<String, Object> params = new HashMap<>();
        params.put("account", account);
        HttpReply reply = httpTransport.syncPost(url, params);
        return buildOperationResult(reply);
    }

    @Override
    public CompletableFuture<OperationResult> sigKey(String account) {
        return asyncCall(() -> syncPostSigKey(account));
    }

    public OperationResult syncRsaKey() {
        String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.rsa_key.name();
        HttpReply reply = httpTransport.syncGet(url);
        return buildOperationResult(reply);
    }

    public OperationResult syncPostRsaKey(String account) {
        String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.rsa_key.name();
        Map<String, Object> params = new HashMap<>();
        params.put("account", account);
        HttpReply reply = httpTransport.syncPost(url, params);
        return buildOperationResult(reply);
    }

    @Override
    public CompletableFuture<OperationResult> rsaKey(String account) {
        return asyncCall(() -> syncPostRsaKey(account));
    }

    @Override
    public CompletableFuture<OperationResult> rsaKey() {
        return asyncCall(this::syncRsaKey);
    }

    public OperationResult syncBlsKey() {
        String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.bls_key.name();
        HttpReply reply = httpTransport.syncGet(url);
        return buildOperationResult(reply);
    }

    public OperationResult syncPostBlsKey(String account) {
        String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.bls_key.name();
        Map<String, Object> params = new HashMap<>();
        params.put("account", account);
        HttpReply reply = httpTransport.syncPost(url, params);
        return buildOperationResult(reply);
    }

    @Override
    public CompletableFuture<OperationResult> blsKey(String account) {
        return asyncCall(() -> syncPostBlsKey(account));
    }

    @Override
    public CompletableFuture<OperationResult> blsKey() {
        return asyncCall(this::syncBlsKey);
    }

    public Session syncLogin(String organization, String account, String scopes, String credentials) {
        try {
            String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.login.name();

            String toSign = organization + "\n" + getClientPublicKey() + "\n" + scopes;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);

            Map<String, Object> params = new HashMap<>();
            params.put("organization", organization);
            params.put("account", account);
            params.put("scopes", scopes);
            params.put("credentials", credentials);
            params.put("signature", signature);
            params.put("x-key", getClientPublicKey());
            params.put("x-sig-key", KeysProvider.derivePublicSigKey(getApiContext().getClientPrivateKey()));
            params.put("x-rsa-key", KeysProvider.derivePublicRSAKey(getApiContext().getClientPrivateKey()));
            BLSKeyPair blsKeyPair = getBlsKeyPair();
            if (blsKeyPair != null && blsKeyPair.getPublicKey() != null) {
                params.put("x-bls-key", Base58.encode(blsKeyPair.getPublicKey()));
            }
            params.put("x-iv", Hex.toHexString(iv));
            addDelegateSignature(params);

            HttpReply reply = httpTransport.syncPost(url, params);
            OperationResult result = reply != null ? buildOperationResult(reply) : null;
            if (result != null && result.getData() != null) {
                return Session.parse(result.getData(), getApiContext());
            } else {
                logger.error("Failed login" + (result != null ? " " + result.getMessage() : ""));
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed login", e);
            return null;
        }
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes) {
        return asyncCall(() -> syncLogin(organization, account, scopes, null));
    }

    @Override
    public CompletableFuture<Session> login(String organization, String account, String scopes, String credentials) {
        return asyncCall(() -> syncLogin(organization, account, scopes, credentials));
    }

    public Session syncProxyLogin(String node, String organization, String account, String scopes) {
        try {
            String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.proxy_login.name();

            Map<String, Object> params = buildProxyLoginParams(node, organization, account, scopes);

            HttpReply reply = httpTransport.syncPost(url, params);
            OperationResult result = reply != null ? buildOperationResult(reply) : null;

            if (result instanceof Forward) {
                String decryptedResult = decryptProxyParams(result);
                result = decryptedResult != null ? OperationResultSerializer.from(decryptedResult) : null;
            }

            if (result != null && result.getData() != null) {
                return Session.parse(result.getData(), getApiContext());
            } else {
                logger.error("Failed login" + (result != null ? " " + result.getMessage() : ""));
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed login", e);
            return null;
        }
    }

    @Override
    public CompletableFuture<Session> proxyLogin(String node, String organization, String account, String scopes) {
        return asyncCall(() -> syncProxyLogin(node, organization, account, scopes));
    }

    public OperationResult syncLogout(Session session) {
        try {
            String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.logout.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            HttpReply reply = getAuthPost(session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed logout", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> logout(Session session) {
        return asyncCall(() -> syncLogout(session));
    }

    public OperationResult syncTerms(Session session, TermsOptions options) {
        try {
            String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.terms.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            String termsOptions = Utils.getGson().toJson(options);
            params.put("options", termsOptions);
            params.put("signature", sign(termsOptions));
            HttpReply reply = getAuthPost(session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed terms", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> terms(Session session, TermsOptions options) {
        return asyncCall(() -> syncTerms(session, options));
    }

    public HttpReply authPost(RequestType requestType, Session session, String url, Map<String, Object> params, Integer timeout) {
        String feeLimits = getFeeLimits(requestType);
        if (feeLimits != null) {
            params.put("feeLimits", feeLimits);
        }

        if (session.getProxyNode() == null) {
            if (config.isEncrypted()) {
                Map<String, Object> encParams = encryptParams(session, url, params);

                String encUrl = apiUrl + "/" + getClientVersion() + "/" + RequestType.enc.name();

                HttpReply reply = httpTransport.syncPost(encUrl, encParams);

                OperationResult result = buildOperationResult(reply);

                if (result.getData() != null) {
                    String decoded = decryptResults(result);
                    return new HttpReply(reply.getStatusCode(), decoded, reply.getReplyHeaders());
                } else {
                    return null;
                }
            } else {
                return getAuthPost(session, url, params, timeout);
            }
        } else {
            return forwardRequest(session, url, params);
        }
    }

    private HttpReply getAuthPost(Session session, String url, Map<String, Object> params, Integer timeout) {
        HttpReply reply = httpTransport.authPost(session, url, params, timeout);

        if (config.isValidateHeaders()) {
            try {
                Map<String, String> headers = new HashMap<>();
                if (reply.getReplyHeaders() != null) {
                    for (Header h : reply.getReplyHeaders()) {
                        headers.put(h.getName().toLowerCase(), h.getValue());
                    }
                }

                String in = headers.get("x-in");
                String out = headers.get("x-out");
                String sig = headers.get("x-iosig");
                String ts = headers.get("x-ts");
                if (in != null && out != null && sig != null && ts != null) {
                    byte[] outChecksum = replyDigest.get().digest(reply.getBody().getBytes(StandardCharsets.UTF_8));
                    boolean hashEqual = Arrays.equals(outChecksum, io.ipfs.multibase.Base58.decode(out));
                    if (!hashEqual) {
                        logger.error("Failed API call, reply hash not matching");
                        return null;
                    }

                    String chained = ts + "\n" + in + "\n" + out;
                    boolean match = KeysProvider.verifyAccountSignature(getApiContext().getServerSigKey(), sig, chained.getBytes(StandardCharsets.UTF_8));

                    if (!match) {
                        logger.error("Failed API call, reply signature not matching");
                        return null;
                    }
                } else {
                    logger.error("Failed API call, missing reply headers");
                    return null;
                }
            } catch (Exception e) {
                logger.error("Failed validating reply headers", e);
                return null;
            }
        }

        return reply;
    }

    public HttpReply authPostDownload(RequestType requestType, Session session, String url, Map<String, Object> params, Integer timeout, int bufferSize, Consumer<byte[]> callback) {
        String feeLimits = getFeeLimits(requestType);
        if (feeLimits != null) {
            params.put("feeLimits", feeLimits);
        }

        if (session.getProxyNode() == null) {
            if (config.isEncrypted()) {
                Map<String, Object> encParams = encryptParams(session, url, params);

                String encUrl = apiUrl + "/" + getClientVersion() + "/" + RequestType.enc.name();
                HttpReply reply = httpTransport.syncDownloadPost(encUrl, encParams, bufferSize, callback);

                OperationResult result = buildOperationResult(reply);

                if (result.getData() != null) {
                    String decoded = decryptResults(result);
                    return new HttpReply(reply.getStatusCode(), decoded, reply.getReplyHeaders());
                } else {
                    return null;
                }
            } else {
                return httpTransport.authDownloadPost(session, url, params, bufferSize, callback, timeout);
            }
        } else {
            return forwardRequest(session, url, params);
        }
    }

    private Map<String, Object> encryptParams(Session session, String url, Map<String, Object> params) {
        byte[] iv = KeysProvider.generateIV();
        KeyExchange keyExchange = KeysProvider.getInstance();
        String body = Utils.getGson().toJson(params);

        Map<String, Object> headers = new HashMap<>();
        String nonce = Long.toString(session.getNonce().incrementAndGet());
        headers.put("x-api-key", session.getApiKey());
        headers.put("x-nonce", nonce);
        String toSign = url.substring(url.lastIndexOf("/", url.lastIndexOf("/") - 1))
                + "\n" + session.getApiKey()
                + "\n" + nonce
                + "\n" + (body.isEmpty() ? "{}" : body);
        String signature = Hash.signRequestB64(session.getSecret(), toSign);
        headers.put("x-sig", signature);

        Map<String, Object> data = new HashMap<>();
        data.put("call", url.substring(url.lastIndexOf("/") + 1));
        data.put("headers", headers);
        data.put("body", body);

        SecretKey secretKey = keyExchange.sharedSecret(getApiContext().getClientPrivateKey(), getApiContext().getServerPublicKey(), null);
        byte[] encrypted = keyExchange.encrypt(secretKey, Utils.getGson().toJson(data).getBytes(StandardCharsets.UTF_8), getApiContext().getSeed(), iv);

        Map<String, Object> encParams = new HashMap<>();
        encParams.put("x-enc", Base64.encodeBase64String(encrypted));
        encParams.put("x-iv", Hex.toHexString(iv));
        encParams.put("x-key", getApiContext().getPublicKey());

        return encParams;
    }

    private String decryptResults(OperationResult result) {
        KeyExchange keyExchange = KeysProvider.getInstance();
        SecretKey secretKey = keyExchange.sharedSecret(getApiContext().getClientPrivateKey(), getApiContext().getServerPublicKey(), null);

        Map<String, Object> encReply = Utils.getGson().fromJson((String) result.getData(), Map.class);
        byte[] riv = Hex.decode(encReply.get("x-iv").toString());
        byte[] rdata = keyExchange.decrypt(secretKey, Base64.decodeBase64(encReply.get("msg").toString()), getApiContext().getSeed(), riv);
        return new String(rdata, StandardCharsets.UTF_8).replaceAll("\0", "");
    }

    private HttpReply forwardRequest(Session session, String url, Map<String, Object> params) {
        String fwdUrl = apiUrl + "/" + getClientVersion() + "/" + RequestType.forwarded_request.name();

        Map<String, Object> fwdParams = encryptProxyParams(session, url, params, session.getProxyNode(), session.getTempKey());

        HttpReply reply = httpTransport.syncPost(fwdUrl, fwdParams);
        OperationResult result = reply != null ? buildOperationResult(reply) : null;

        if (result instanceof Forward) {
            String decryptedResult = decryptProxyParams(result);
            return new HttpReply(200, decryptedResult, reply.getReplyHeaders());
        } else {
            return new HttpReply(200, Utils.getGson().toJson(result), reply != null ? reply.getReplyHeaders() : null);
        }
    }

    public OperationResult syncStatus(Session session) {
        try {
            RequestType requestType = RequestType.status;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed status", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> status(Session session) {
        return asyncCall(() -> syncStatus(session));
    }

    public OperationResult syncCreateTable(Session session, String scope, String table, CreateOptions options) {
        try {
            RequestType requestType = RequestType.create;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getCreateTimeoutSec() : null);
            if (reply != null) {
                return buildOperationResult(reply);
            } else {
                return new AccessError(null, "Failed building reply");
            }
        } catch (Exception e) {
            logger.error("Failed create", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> createTable(Session session, String scope, String table, CreateOptions options) {
        return asyncCall(() -> syncCreateTable(session, scope, table, options));
    }

    public OperationResult syncDropTable(Session session, String scope, String table, DropOptions options) {
        try {
            RequestType requestType = RequestType.drop;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getDropTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed create", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> dropTable(Session session, String scope, String table, DropOptions options) {
        return asyncCall(() -> syncDropTable(session, scope, table, options));
    }

    public OperationResult syncUpdateLayout(Session session, String scope, String table, String layout) {
        try {
            RequestType requestType = RequestType.update_layout;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            params.put("layout", layout);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed create", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> updateLayout(Session session, String scope, String table, String layout) {
        return asyncCall(() -> syncUpdateLayout(session, scope, table, layout));
    }

    public OperationResult syncWrite(Session session, String scope, Records records, WriteOptions options) {
        if (options.isAllowLocalBatching()) {
            try {
                RecordBatchLocation location = new RecordBatchLocation(session.getAccount(), session.getOrganization(), scope, records.getTable(), options);

                final BatchData currentBatch = batchHelper.getBatch(location, options.getWriteTimeoutSec() + options.getBatchingOptions().getWaitTimeMs());
                currentBatch.addRecord(records);

                batchHelper.checkBatch(currentBatch, options.getBatchingOptions(), () -> doBatchWrite(session, currentBatch, options));

                //TODO: 2 stages, first a succes for adding to the batch then the real result.
                // To add tests that sync and async writes work as expected, a sync write from client with sync signing should provide both guarantees when done
                return new Pending(
                        new OperationScope(ApiOperationType.WRITE, session.getAccount(), session.getOrganization(), scope, records.getTable()),
                        null
                );
            } catch (Exception e) {
                logger.error("Failed write", e);
                return new AccessError(null, e.toString());
            }
        } else {
            return doWrite(session, scope, records, options);
        }
    }

    public OperationResult doBatchWrite(Session session, BatchData batch, WriteOptions options) {
        try {
            if (batch.getDispatched().compareAndSet(false, true)) {
                Records records = new Records(batch.getLocation().getTable(), new ArrayList<>(batch.getItems().get(0).getItems()), null, null);
                for (int i = 1; i < batch.getItems().size(); i++) {
                    records.getItems().addAll(batch.getItems().get(i).getItems());
                }

                return doWrite(session, batch.getLocation().getScope(), records, batch.getLocation().getWriteOptions());
            } else {
                return new Success(
                        new OperationScope(ApiOperationType.WRITE, session.getAccount(), session.getOrganization(), batch.getLocation().getScope(), batch.getLocation().getTable()),
                        null
                );
            }
        } catch (Exception e) {
            logger.error("Failed write", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult doWrite(Session session, String scope, Records records, WriteOptions options) {
        try {
            RequestType requestType = RequestType.write;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", records.getTable());

            addIntegritySignatureIfConfigured(records, session, scope, params);

            DataLayout layout = getTableLayout(session, scope, records.getTable());
            ContentEncoder encoder = layout != null ? contentEncoder : Encoding.getJsonContentEncoder();
            if (encoder != Encoding.getDefaultContentEncoder()) {
                params.put("enc", encoder.getType());
            }
            params.put("records", encoder.encode(records, layout));

            if (options != null) {
                params.put("options", Utils.getWriteOptionsJsonAdapter().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getWriteTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed write", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> write(Session session, String scope, Records records, WriteOptions options) {
        //TODO: start hash writing in parallel
        return asyncCall(() -> syncWrite(session, scope, records, options));
    }

    public OperationResult syncRead(Session session, String scope, String table, Filter filter, ReadOptions options) {
        try {
            RequestType requestType = RequestType.read;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = createParams();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed read", e);
            return new AccessError(null, e.toString());
        }
    }

    private static Map<String, Object> createParams() {
        Map<String, Object> params = new HashMap<>();
        return params;
    }

    @Override
    public CompletableFuture<OperationResult> read(Session session, String scope, String table, Filter filter, ReadOptions options) {
        //TODO: start hash reading from blockchain in parallel
        //TODO: helper functions to have the option to check data hashes against blockchain locally
        return asyncCall(() -> syncRead(session, scope, table, filter, options));
    }

    public OperationResult syncCount(Session session, String scope, String table, Filter filter, ReadOptions options) {
        try {
            RequestType requestType = RequestType.count;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = createParams();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed count", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> count(Session session, String scope, String table, Filter filter, ReadOptions options) {
        return asyncCall(() -> syncCount(session, scope, table, filter, options));
    }

    public OperationResult syncDelete(Session session, String scope, String table, Filter filter, DeleteOptions options) {
        try {
            String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.delete.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(RequestType.delete, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed delete", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> delete(Session session, String scope, String table, Filter filter, DeleteOptions options) {
        return asyncCall(() -> syncDelete(session, scope, table, filter, options));
    }

    public OperationResult syncHashes(Session session, String scope, String table, Filter filter, ReadOptions options) {
        try {
            RequestType requestType = RequestType.hashes;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed reading hashes", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> hashes(Session session, String scope, String table, Filter filter, ReadOptions options) {
        //TODO: option to read blockchain directly
        return asyncCall(() -> syncHashes(session, scope, table, filter, options));
    }

    public OperationResult syncDownloadTable(Session session, String scope, String table, Filter filter, FileFormat format, ReadOptions options) {
        try {
            RequestType requestType = RequestType.download_table;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            params.put("format", format.name());
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed download table", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> downloadTable(Session session, String scope, String table, Filter filter, FileFormat format, ReadOptions options) {
        return asyncCall(() -> syncDownloadTable(session, scope, table, filter, format, options));
    }

    public OperationResult syncDownloadDataset(Session session, String did, ReadOptions options) {
        try {
            RequestType requestType = RequestType.download_dataset;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("did", did);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed download dataset", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> downloadDataset(Session session, String did, ReadOptions options) {
        return asyncCall(() -> syncDownloadDataset(session, did, options));
    }

    public OperationResult syncPublishDataset(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String scope, String table, Filter filter, FileFormat format, BigDecimal price, String token, Long pageorder, PublishDatasetOptions options) {
        try {
            RequestType requestType = RequestType.publish_dataset;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("did", did);
            params.put("name", name);
            params.put("description", description);
            params.put("license", license);
            params.put("metadata", metadata);
            params.put("weave", weave);
            params.put("full_description", fullDescription);
            params.put("logo", logo);
            params.put("category", category);
            params.put("scope", scope);
            params.put("table", table);
            params.put("format", format.name());
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            params.put("price", price != null ? price.toString() : null);
            params.put("token", token);
            params.put("pageorder", pageorder);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed publish", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> publishDataset(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String scope, String table, Filter filter, FileFormat format, BigDecimal price, String token, Long pageorder, PublishDatasetOptions options) {
        return asyncCall(() -> syncPublishDataset(session, did, name, description, license, metadata, weave, fullDescription, logo, category, scope, table, filter, format, price, token, pageorder, options));
    }

    public OperationResult syncEnableProduct(Session session, String did, String productType, Boolean active) {
        try {
            RequestType requestType = RequestType.enable_product;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("did", did);
            params.put("productType", productType);
            params.put("active", active);

            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed enable product", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> enableProduct(Session session, String did, String productType, Boolean active) {
        return asyncCall(() -> syncEnableProduct(session, did, productType, active));
    }

    public OperationResult syncRunTask(Session session, String did, ComputeOptions options) {
        try {
            RequestType requestType = RequestType.run_task;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("did", did);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed task run", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> runTask(Session session, String did, ComputeOptions options) {
        return asyncCall(() -> syncRunTask(session, did, options));
    }

    public OperationResult syncPublishTask(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String task, BigDecimal price, String token, Long pageorder, PublishTaskOptions options) {
        try {
            RequestType requestType = RequestType.publish_task;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("did", did);
            params.put("name", name);
            params.put("description", description);
            params.put("license", license);
            params.put("metadata", metadata);
            params.put("weave", weave);
            params.put("full_description", fullDescription);
            params.put("logo", logo);
            params.put("category", category);
            params.put("task", task);
            params.put("price", price != null ? price.toString() : null);
            params.put("token", token);
            params.put("pageorder", pageorder);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getComputeTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed publish", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> publishTask(Session session, String did, String name, String description, String license, String metadata, String weave, String fullDescription, String logo, String category, String task, BigDecimal price, String token, Long pageorder, PublishTaskOptions options) {
        return asyncCall(() -> syncPublishTask(session, did, name, description, license, metadata, weave, fullDescription, logo, category, task, price, token, pageorder, options));
    }

    public OperationResult syncSubscribe(Session session, String scope, String table, Filter filter, SubscribeOptions options, BiConsumer<String, Records> onData) {
        try {
            RequestType requestType = RequestType.subscribe;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);

            //TODO: HTTP support, register onData event, perioding polling

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed subscribe", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> subscribe(Session session, String scope, String table, Filter filter, SubscribeOptions options, BiConsumer<String, Records> onData) {
        return asyncCall(() -> syncSubscribe(session, scope, table, filter, options, onData));
    }

    public OperationResult syncUnsubscribe(Session session, String subscriptionId) {
        try {
            RequestType requestType = RequestType.unsubscribe;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("subscriptionId", subscriptionId);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed unsubscribe", e);
            return new AccessError(null, e.toString());
        }
    }


    @Override
    public CompletableFuture<OperationResult> unsubscribe(Session session, String subscriptionId) {
        return asyncCall(() -> syncUnsubscribe(session, subscriptionId));
    }


    public OperationResult syncCompute(Session session, String image, ComputeOptions options) {
        try {
            RequestType requestType = RequestType.compute;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("image", image);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getTimeoutSec() : null);

            if (reply != null && reply.getStatusCode() != 200) {
                logger.error("Failed request " + reply.getStatusCode() + "\n" + reply.getBody());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> compute(Session session, String image, ComputeOptions options) {
        return asyncCall(() -> syncCompute(session, image, options));
    }

    @Override
    public CompletableFuture<OperationResult> getImage(String image, Session session, Consumer<byte[]> callback) {
        return asyncCall(() -> syncGetImage(image, session, callback));
    }

    private OperationResult syncGetImage(String image, Session session, Consumer<byte[]> callback) {
        try {
            String url = apiUrl + "/" + getClientVersion() + "/" + RequestType.get_image.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("image", Base58.encode(image.getBytes(StandardCharsets.UTF_8)));
            HttpReply reply = authPostDownload(RequestType.get_image, session, url, params, null, DOWNLOAD_BUFFER_SIZE, callback);
            if (reply != null && reply.getStatusCode() == 200) {
                return new Success(null, reply.getBody());
            } else {
                return new AccessError(null, reply != null ? reply.getBody() : "No reply");
            }
        } catch (Exception e) {
            logger.error("Failed getting docker image", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncFLearn(Session session, String image, FLOptions options) {
        try {
            RequestType requestType = RequestType.f_learn;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("image", image);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getTimeoutSec() : null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed federated learning", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> flearn(Session session, String image, FLOptions options) {
        return asyncCall(() -> syncFLearn(session, image, options));
    }

    @Override
    public CompletableFuture<OperationResult> splitLearn(Session session, String image, SplitLearnOptions options) {
        return asyncCall(() -> syncSplitLearn(session, image, options));
    }

    public OperationResult syncSplitLearn(Session session, String image, SplitLearnOptions options) {
        try {
            RequestType requestType = RequestType.split_learn;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("image", image);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getTimeoutSec() : null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed split learning", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncHEGetInputs(Session session, List<Object> datasources, List<Object> args) {
        try {
            RequestType requestType = RequestType.he_get_inputs;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("datasources", Utils.getGson().toJson(datasources));
            if (args != null) {
                params.put("args", Utils.getGson().toJson(args));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed HE get inputs", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> heGetInputs(Session session, List<Object> datasources, List<Object> args) {
        return asyncCall(() -> syncHEGetInputs(session, datasources, args));
    }

    public OperationResult syncHEGetOutputs(Session session, String encoded, List<Object> args) {
        try {
            RequestType requestType = RequestType.he_get_outputs;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("encoded", encoded);
            if (args != null) {
                params.put("args", Utils.getGson().toJson(args));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed HE get outputs", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> heGetOutputs(Session session, String encoded, List<Object> args) {
        return asyncCall(() -> syncHEGetOutputs(session, encoded, args));
    }

    public OperationResult syncHEEncode(Session session, List<Object> items) {
        try {
            RequestType requestType = RequestType.he_encode;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("items", Utils.getGson().toJson(items));
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed HE ncode", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> heEncode(Session session, List<Object> items) {
        return asyncCall(() -> syncHEEncode(session, items));
    }


    public OperationResult syncPluginCall(Session session, String plugin, String request, Map<String, Object> args, int timeoutSec) {
        try {
            RequestType requestType = RequestType.plugin_call;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("plugin", plugin);
            params.put("request", request);
            params.put("args", args);
            HttpReply reply = authPost(requestType, session, url, params, timeoutSec);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed plugin call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> pluginCall(Session session, String plugin, String request, Map<String, Object> args, int timeoutSec) {
        return asyncCall(() -> syncPluginCall(session, plugin, request, args, timeoutSec));
    }

    public OperationResult syncZkProof(Session session, String scope, String table, String gadget, String gadgetParams, List<String> fields, Filter filter, ZKOptions options) {
        try {
            RequestType requestType = RequestType.zk_proof;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            params.put("gadget", gadget);
            params.put("params", gadgetParams);
            params.put("fields", Utils.getGson().toJson(fields));
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed generating proof", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> zkProof(Session session, String scope, String table, String gadget, String params, List<String> fields, Filter filter, ZKOptions options) {
        return asyncCall(() -> syncZkProof(session, scope, table, gadget, params, fields, filter, options));
    }

    public OperationResult syncZkDataProof(Session session, String gadget, String gadgetParams, List<Object> values, ZKOptions options) {
        try {
            RequestType requestType = RequestType.zk_data_proof;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("gadget", gadget);
            params.put("params", gadgetParams);
            params.put("values", Utils.getGson().toJson(values));
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed generating proof", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> zkDataProof(Session session, String gadget, String params, List<Object> values, ZKOptions options) {
        return asyncCall(() -> syncZkDataProof(session, gadget, params, values, options));
    }

    public OperationResult syncProofsLastHash(Session session, String scope, String table) {
        try {
            RequestType requestType = RequestType.proofs_last_hash;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);

            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed reading hash", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> proofsLastHash(Session session, String scope, String table) {
        return asyncCall(() -> syncProofsLastHash(session, scope, table));
    }

    public OperationResult syncUpdateProofs(Session session, String scope, String table) {
        try {
            RequestType requestType = RequestType.update_proofs;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);

            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed reading proofs", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> updateProofs(Session session, String scope, String table) {
        return asyncCall(() -> syncUpdateProofs(session, scope, table));
    }

    public OperationResult syncMPC(Session session, String scope, String table, String algo, List<String> fields, Filter filter, MPCOptions options) {
        try {
            RequestType requestType = RequestType.mpc;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            params.put("algo", algo);
            params.put("fields", Utils.getGson().toJson(fields));
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed MPC", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> mpc(Session session, String scope, String table, String algo, List<String> fields, Filter filter, MPCOptions options) {
        return asyncCall(() -> syncMPC(session, scope, table, algo, fields, filter, options));
    }

    public OperationResult syncMPCInitProtocol(Session session, String computationId, int nodeIndex, String scope, String table, String algo, List<String> fields, Filter filter, Map<String, Integer> indexedPeers, MPCOptions options) {
        try {
            RequestType requestType = RequestType.mpc_init;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("computationId", computationId);
            params.put("nodeIndex", nodeIndex);
            params.put("scope", scope);
            params.put("table", table);
            params.put("algo", algo);
            params.put("indexedPeers", Utils.getGson().toJson(indexedPeers));
            params.put("fields", Utils.getGson().toJson(fields));
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getReadTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed MPC protocol init", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> mpcInitProtocol(Session session, String computationId, int nodeIndex, String scope, String table, String algo, List<String> fields, Filter filter, Map<String, Integer> indexedPeers, MPCOptions options) {
        return asyncCall(() -> syncMPCInitProtocol(session, computationId, nodeIndex, scope, table, algo, fields, filter, indexedPeers, options));
    }

    public OperationResult syncMPCProtocol(Session session, String computationId, String message) {
        try {
            RequestType requestType = RequestType.mpc_proto;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("computationId", computationId);
            params.put("message", message);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed MPC protocol call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> mpcProtocol(Session session, String computationId, String message) {
        return asyncCall(() -> syncMPCProtocol(session, computationId, message));
    }

    public OperationResult syncProxyEncryptSecret(Session session, String scope, String table, ProxyEncryptedData pre) {
        try {
            RequestType requestType = RequestType.proxy_encrypt;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            params.put("pre", pre.toJson());
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed MPC protocol call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> proxyEncryptSecret(Session session, String scope, String table, ProxyEncryptedData pre) {
        return asyncCall(() -> syncProxyEncryptSecret(session, scope, table, pre));
    }

    public OperationResult syncProxyReencryptSecret(Session session, String scope, String table) {
        try {
            RequestType requestType = RequestType.proxy_reencrypt;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed proxy reencrypt call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> proxyReEncryptSecret(Session session, String scope, String table) {
        return asyncCall(() -> syncProxyReencryptSecret(session, scope, table));
    }

    public OperationResult syncBlindSignature(Session session, String blinded) {
        try {
            RequestType requestType = RequestType.blind_signature;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("blinded", blinded);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed blind signature call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> blindSignature(Session session, String blinded) {
        return asyncCall(() -> syncBlindSignature(session, blinded));
    }

    public OperationResult syncStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        try {
            RequestType requestType = RequestType.storage_proof;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            params.put("challenge", challenge);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed storage proof", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> storageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        return asyncCall(() -> syncStorageProof(session, scope, table, filter, challenge, options));
    }

    public OperationResult syncZkStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        try {
            RequestType requestType = RequestType.zk_storage_proof;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            params.put("challenge", challenge);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed storage proof", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> zkStorageProof(Session session, String scope, String table, Filter filter, String challenge, ReadOptions options) {
        return asyncCall(() -> syncZkStorageProof(session, scope, table, filter, challenge, options));
    }

    public OperationResult syncMerkleTree(Session session, String scope, String table, Filter filter, String salt, ReadOptions options) {
        try {
            RequestType requestType = RequestType.merkle_tree;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            params.put("salt", salt);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed merkle tree call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> merkleTree(Session session, String scope, String table, Filter filter, String salt, ReadOptions options) {
        return asyncCall(() -> syncMerkleTree(session, scope, table, filter, salt, options));
    }

    public OperationResult syncMerkleProof(Session session, String scope, String table, String hash) {
        try {
            RequestType requestType = RequestType.merkle_proof;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            params.put("hash", hash);
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed merkle proof call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> merkleProof(Session session, String scope, String table, String hash) {
        return asyncCall(() -> syncMerkleProof(session, scope, table, hash));
    }

    public OperationResult syncZkMerkleTree(Session session, String scope, String table, Filter filter, String salt, Integer rounds, Integer seed, ZKOptions options) {
        try {
            RequestType requestType = RequestType.zk_merkle_tree;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            params.put("rounds", rounds);
            params.put("seed", seed);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            params.put("salt", salt);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed zk merkle tree call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> zkMerkleTree(Session session, String scope, String table, Filter filter, String salt, Integer rounds, Integer seed, ZKOptions options) {
        return asyncCall(() -> syncZkMerkleTree(session, scope, table, filter, salt, rounds, seed, options));
    }

    public OperationResult syncRootHash(Session session, String scope, String table) {
        try {
            RequestType requestType = RequestType.root_hash;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed root hash call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> rootHash(Session session, String scope, String table) {
        return asyncCall(() -> syncRootHash(session, scope, table));
    }

    public OperationResult syncVerifyDataSignature(Session session, String signer, String signature, String data) {
        try {
            RequestType requestType = RequestType.verify_data_signature;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("signer", signer);
            params.put("signature", signature);
            params.put("data", data);
            HttpReply reply = authPost(requestType, session, url, params, null);
            if (reply != null) {
                logger.error("Failed request " + reply.getStatusCode());
            }

            return OperationResultSerializer.from(reply != null ? reply.getBody() : null);
        } catch (Exception e) {
            logger.error("Failed verify data signature call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> verifyDataSignature(Session session, String signer, String signature, String data) {
        return asyncCall(() -> syncVerifyDataSignature(session, signer, signature, data));
    }

    public OperationResult syncTaskLineage(Session session, String taskId) {
        try {
            RequestType requestType = RequestType.task_lineage;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("taskId", taskId);
            HttpReply reply = authPost(requestType, session, url, params, null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> taskLineage(Session session, String taskId) {
        return asyncCall(() -> syncTaskLineage(session, taskId));
    }

    public OperationResult syncHashCheckpoint(Session session, Boolean enable) {
        try {
            RequestType requestType = RequestType.hash_checkpoint;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("enable", enable);
            HttpReply reply = authPost(requestType, session, url, params, null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> hashCheckpoint(Session session, Boolean enable) {
        return asyncCall(() -> syncHashCheckpoint(session, enable));
    }

    public OperationResult syncVerifyTaskLineage(Session session, Map<String, Object> metadata) {
        try {
            RequestType requestType = RequestType.verify_task_lineage;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("metadata", metadata);
            HttpReply reply = authPost(requestType, session, url, params, null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> verifyTaskLineage(Session session, Map<String, Object> metadata) {
        return asyncCall(() -> syncVerifyTaskLineage(session, metadata));
    }

    public OperationResult syncTaskOutputData(Session session, String taskId, OutputOptions options) {
        try {
            RequestType requestType = RequestType.task_output_data;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("taskId", taskId);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }

            HttpReply reply = authPost(requestType, session, url, params, null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> taskOutputData(Session session, String taskId, OutputOptions options) {
        return asyncCall(() -> syncTaskOutputData(session, taskId, options));
    }

    private OperationResult syncHistory(Session session, String scope, String table, Filter filter, HistoryOptions options) {
        try {
            RequestType requestType = RequestType.history;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Throwable t) {
            String message = String.format("Error getting history for filter=%s, options=%s, ex=%s",
                    Utils.getGson().toJson(filter),
                    Utils.getGson().toJson(options),
                    t);
            logger.error(message);
            return new AccessError(null, message);
        }
    }

    @Override
    public CompletableFuture<OperationResult> history(Session session, String scope, String table, Filter filter, HistoryOptions options) {
        return asyncCall(() -> syncHistory(session, scope, table, filter, options));
    }

    private OperationResult syncWriters(Session session, String scope, String table, Filter filter) {
        try {
            RequestType requestType = RequestType.writers;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Throwable t) {
            String message = String.format("Error getting writers for filter=%s, table=%s, ex=%s",
                    Utils.getGson().toJson(filter),
                    table,
                    t);
            logger.error(message);
            return new AccessError(null, message);
        }
    }

    @Override
    public CompletableFuture<OperationResult> writers(Session session, String scope, String table, Filter filter) {
        return asyncCall(() -> syncWriters(session, scope, table, filter));
    }

    private OperationResult syncTasks(Session session, String scope, String table, Filter filter) {
        try {
            RequestType requestType = RequestType.tasks;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Throwable t) {
            String message = String.format("Error getting writer-tasks for filter=%s, table=%s, ex=%s",
                    Utils.getGson().toJson(filter),
                    table,
                    t);
            logger.error(message);
            return new AccessError(null, message);
        }
    }

    @Override
    public CompletableFuture<OperationResult> tasks(Session session, String scope, String table, Filter filter) {
        return asyncCall(() -> syncTasks(session, scope, table, filter));
    }

    private OperationResult syncLineage(Session session, String scope, String table, Filter filter) {
        try {
            RequestType requestType = RequestType.lineage;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            if (filter != null) {
                params.put("filter", Utils.getGson().toJson(filter));
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Throwable t) {
            String message = String.format("Error getting lineage for filter=%s, table=%s, ex=%s",
                    Utils.getGson().toJson(filter),
                    table,
                    t);
            logger.error(message);
            return new AccessError(null, message);
        }
    }

    @Override
    public CompletableFuture<OperationResult> lineage(Session session, String scope, String table, Filter filter) {
        return asyncCall(() -> syncLineage(session, scope, table, filter));
    }


    public OperationResult syncDeployOracle(Session session, String oracleType, String targetBlockchain, DeployOptions options) {
        try {
            RequestType requestType = RequestType.deploy_oracle;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("oracleType", oracleType);
            params.put("targetBlockchain", targetBlockchain);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }

            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getTimeoutSec() : null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> deployOracle(Session session, String oracleType, String targetBlockchain, String source, DeployOptions options) {
        return asyncCall(() -> syncDeployOracle(session, oracleType, targetBlockchain, options));
    }

    //messaging interface
    public OperationResult syncPostMessage(Session session, String targetInboxKey, String message, MessageOptions options) {
        try {
            RequestType requestType = RequestType.deploy_oracle;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("targetInboxKey", targetInboxKey);
            params.put("message", message);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }

            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getOpTimeoutSec() : null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> postMessage(Session session, String targetInboxKey, String message, MessageOptions options) {
        return asyncCall(() -> syncPostMessage(session, targetInboxKey, message, options));
    }

    public OperationResult syncPollMessages(Session session, String inboxKey, MessageOptions options) {
        try {
            RequestType requestType = RequestType.deploy_oracle;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("inboxKey", inboxKey);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }

            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getOpTimeoutSec() : null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> pollMessages(Session session, String inboxKey, MessageOptions options) {
        return asyncCall(() -> syncPollMessages(session, inboxKey, options));
    }


    public OperationResult syncDeployFeed(Session session, String image, DeployOptions options) {
        try {
            RequestType requestType = RequestType.deploy_feed;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("image", image);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }

            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getTimeoutSec() : null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> deployFeed(Session session, String image, DeployOptions options) {
        return asyncCall(() -> syncDeployFeed(session, image, options));
    }

    public OperationResult syncRemoveFeed(Session session, String feedId) {
        try {
            RequestType requestType = RequestType.remove_feed;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("feedId", feedId);

            HttpReply reply = authPost(requestType, session, url, params, null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> removeFeed(Session session, String feedId) {
        return asyncCall(() -> syncRemoveFeed(session, feedId));
    }

    public OperationResult syncStartFeed(Session session, String feedId, ComputeOptions options) {
        try {
            RequestType requestType = RequestType.start_feed;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("feedId", feedId);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }

            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getTimeoutSec() : null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> startFeed(Session session, String feedId, ComputeOptions options) {
        return asyncCall(() -> syncStartFeed(session, feedId, options));
    }

    public OperationResult syncStopFeed(Session session, String feedId) {
        try {
            RequestType requestType = RequestType.stop_feed;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("feedId", feedId);

            HttpReply reply = authPost(requestType, session, url, params, null);

            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed compute", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> stopFeed(Session session, String feedId) {
        return asyncCall(() -> syncStopFeed(session, feedId));
    }

    public OperationResult syncBroadcast(Session session, ConsensusMessage message) {
        try {
            int timeout = ReadOptions.DEFAULT_READ_TIMEOUT_SEC;

            RequestType requestType = RequestType.broadcast;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();

            Map<String, Object> params = new HashMap<>();
            params.put("organization", message.getOrganization());
            params.put("account", message.getAccount());
            params.put("scope", message.getScope());
            params.put("table", message.getTable());
            params.put("data", Utils.getMapJsonAdapter().toJson(message.getData()));

            HttpReply reply = authPost(requestType, session, url, params, timeout);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed read", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> broadcast(Session session, ConsensusMessage message) {
        return asyncCall(() -> syncBroadcast(session, message));
    }

    private OperationResult syncCreateUserAccount(Session session, String publicKey, ChainOptions options) {
        try {
            RequestType requestType = RequestType.create_account;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();

            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("publicKey", publicKey);

            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed create account", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> createAccount(Session session, String publicKey) {
        return asyncCall(() -> syncCreateUserAccount(session, publicKey, ChainOptions.DEFAULT));
    }

    private OperationResult syncDeploy(Session session, String contractType, ChainOptions options) {
        try {
            RequestType requestType = RequestType.deploy;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();

            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("contractType", contractType);

            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed deploy", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> deploy(Session session, String contractType) {
        return asyncCall(() -> syncDeploy(session, contractType, ChainOptions.DEFAULT));
    }

    private OperationResult syncCall(Session session, String contractAddress, String scope, String function, byte[] data, ChainOptions options) {
        try {
            RequestType requestType = RequestType.call;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("contractAddress", contractAddress);
            params.put("function", function);

            String encodedData = Base64.encodeBase64String(data);
            params.put("data", encodedData);

            String toSign = session.getOrganization()
                    + "\n" + getClientPublicKey()
                    + "\n" + contractAddress
                    + "\n" + scope
                    + "\n" + function
                    + "\n" + encodedData;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);
            params.put("x-iv", Hex.toHexString(iv));
            params.put("signature", signature);

            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed call", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> call(Session session, String contractAddress, String scope, String function, byte[] data) {
        return asyncCall(() -> syncCall(session, contractAddress, scope, function, data, ChainOptions.DEFAULT));
    }

    private OperationResult syncBalance(Session session, String accountAddress, String scope, String token) {
        try {
            RequestType requestType = RequestType.balance;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("accountAddress", accountAddress);
            params.put("scope", scope);
            params.put("token", token);
            String toSign = session.getOrganization()
                    + "\n" + getClientPublicKey()
                    + "\n" + accountAddress
                    + "\n" + scope
                    + "\n" + token;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);
            params.put("x-iv", Hex.toHexString(iv));
            params.put("signature", signature);

            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed balance", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> balance(Session session, String accountAddress, String scope, String token) {
        return asyncCall(() -> syncBalance(session, accountAddress, scope, token));
    }

    private OperationResult syncTransfer(Session session, String accountAddress, String scope, String token, BigDecimal amount) {
        try {
            RequestType requestType = RequestType.transfer;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("accountAddress", accountAddress);
            params.put("scope", scope);
            params.put("token", token);
            params.put("amount", amount.toString());
            String toSign = session.getOrganization()
                    + "\n" + getClientPublicKey()
                    + "\n" + accountAddress
                    + "\n" + scope
                    + "\n" + token
                    + "\n" + amount;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);
            params.put("x-iv", Hex.toHexString(iv));
            params.put("signature", signature);

            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed balance", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> transfer(Session session, String accountAddress, String scope, String token, BigDecimal amount) {
        return asyncCall(() -> syncTransfer(session, accountAddress, scope, token, amount));
    }

    private OperationResult syncUpdateFees(Session session, String scope, String fees) {
        try {
            RequestType requestType = RequestType.update_fees;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("token", fees);
            String toSign = session.getOrganization()
                    + "\n" + getClientPublicKey()
                    + "\n" + scope
                    + "\n" + fees;
            byte[] iv = KeysProvider.generateIV();
            String signature = signString(toSign, iv);
            params.put("x-iv", Hex.toHexString(iv));
            params.put("signature", signature);

            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed update fees", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> updateFees(Session session, String scope, String fees) {
        return asyncCall(() -> syncUpdateFees(session, scope, fees));
    }

    private OperationResult syncContractState(Session session, String contractAddress, String scope, ChainOptions options) {
        try {
            RequestType requestType = RequestType.contract_state;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();

            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("contractAddress", contractAddress);

            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed retrieving contract state", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> contractState(Session session, String contractAddress, String scope) {
        return asyncCall(() -> syncContractState(session, contractAddress, scope, ChainOptions.DEFAULT));
    }

    private OperationResult syncBroadcastBlock(Session session, String scope, String block, ChainOptions options) {
        try {
            RequestType requestType = RequestType.broadcast_block;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();

            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("block", block);

            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed block broadcast", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> broadcastBlock(Session session, String scope, String block) {
        return asyncCall(() -> syncBroadcastBlock(session, scope, block, ChainOptions.DEFAULT));
    }

    private OperationResult syncBroadcastChain(Session session, String scope, List<String> blocks, ChainOptions options) {
        try {
            RequestType requestType = RequestType.broadcast_chain;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();

            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("blocks", blocks);

            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed chain broadcast", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> broadcastChain(Session session, String scope, List<String> blocks) {
        return asyncCall(() -> syncBroadcastChain(session, scope, blocks, ChainOptions.DEFAULT));
    }

    private OperationResult syncIssueCredentials(Session session, String issuer, String holder, Map<String, Object> credentials, CredentialsOptions options) {
        try {
            RequestType requestType = RequestType.issue_credentials;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();

            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("issuer", issuer);
            params.put("holder", holder);
            params.put("credentials", credentials);

            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed credentials issuing", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> issueCredentials(Session session, String issuer, String holder, Map<String, Object> credentials, CredentialsOptions options) {
        return asyncCall(() -> syncIssueCredentials(session, issuer, holder, credentials, options));
    }

    private OperationResult syncVerifyCredentials(Session session, Map<String, Object> credentials, CredentialsOptions options) {
        try {
            RequestType requestType = RequestType.verify_credentials;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("credentials", credentials);
            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed credentials verification", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> verifyCredentials(Session session, Map<String, Object> credentials, CredentialsOptions options) {
        return asyncCall(() -> syncVerifyCredentials(session, credentials, options));
    }

    private OperationResult syncCreatePresentation(Session session, Map<String, Object> credentials, String subject, CredentialsOptions options) {
        try {
            RequestType requestType = RequestType.create_presentation;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("credentials", credentials);
            params.put("subject", subject);
            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed create presentation", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> createPresentation(Session session, Map<String, Object> credentials, String subject, CredentialsOptions options) {
        return asyncCall(() -> syncCreatePresentation(session, credentials, subject, options));
    }

    private OperationResult syncSignPresentation(Session session, Map<String, Object> presentation, String domain, String challenge, CredentialsOptions options) {
        try {
            RequestType requestType = RequestType.sign_presentation;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("presentation", presentation);
            params.put("domain", domain);
            params.put("challenge", challenge);
            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed presentation signing", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> signPresentation(Session session, Map<String, Object> presentation, String domain, String challenge, CredentialsOptions options) {
        return asyncCall(() -> syncSignPresentation(session, presentation, domain, challenge, options));
    }

    private OperationResult syncVerifyPresentation(Session session, Map<String, Object> signedPresentation, String domain, String challenge, CredentialsOptions options) {
        try {
            RequestType requestType = RequestType.verify_presentation;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("presentation", signedPresentation);
            params.put("domain", domain);
            params.put("challenge", challenge);
            HttpReply reply = authPost(requestType, session, url, params, options.getOpTimeoutSec());
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed presentation signing", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> verifyPresentation(Session session, Map<String, Object> signedPresentation, String domain, String challenge, CredentialsOptions options) {
        return asyncCall(() -> syncVerifyPresentation(session, signedPresentation, domain, challenge, options));
    }

    public OperationResult syncGet(Session session, RequestType requestType, String scope, String table) {
        try {
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("account", session.getAccount());
            if (scope != null) {
                params.put("scope", scope);
            }
            if (table != null) {
                params.put("table", table);
            }
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed " + requestType.name(), e);
            return new AccessError(null, e.toString());
        }
    }

    private OperationResult syncForwardedRequest(Session session, Map<String, Object> msg) {
        try {
            RequestType requestType = RequestType.forwarded_request;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>(msg);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed forwarding", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> forwardedRequest(Session session, Map<String, Object> msg) {
        return asyncCall(() -> syncForwardedRequest(session, msg));
    }

    @Override
    public CompletableFuture<OperationResult> getSidechainDetails(Session session) {
        return asyncCall(() -> syncGet(session, RequestType.get_sidechain_details, null, null));
    }

    @Override
    public CompletableFuture<OperationResult> getNodes(Session session) {
        return asyncCall(() -> syncGet(session, RequestType.get_nodes, null, null));
    }

    @Override
    public CompletableFuture<OperationResult> getScopes(Session session) {
        return asyncCall(() -> syncGet(session, RequestType.get_scopes, null, null));
    }

    @Override
    public CompletableFuture<OperationResult> getTables(Session session, String scope) {
        return asyncCall(() -> syncGet(session, RequestType.get_tables, scope, null));
    }

    @Override
    public CompletableFuture<OperationResult> getTableDefinition(Session session, String scope, String table) {
        return asyncCall(() -> syncGet(session, RequestType.get_table_definition, scope, table));
    }

    @Override
    public CompletableFuture<OperationResult> getNodeConfig(Session session, String nodePublicKey) {
        return asyncCall(() -> syncGet(session, RequestType.get_node_config, null, null));
    }

    @Override
    public CompletableFuture<OperationResult> getAccountNotifications(Session session) {
        return asyncCall(() -> syncGet(session, RequestType.get_account_notifications, null, null));
    }

    private OperationResult syncUpdateConfig(Session session, String path, Map<String, Object> values) {
        try {
            RequestType requestType = RequestType.update_config;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("path", path);
            params.put("values", values);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed update config", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> updateConfig(Session session, String path, Map<String, Object> values) {
        return asyncCall(() -> syncUpdateConfig(session, path, values));
    }

    private OperationResult syncGrantRole(Session session, String account, Set<String> roles) {
        try {
            RequestType requestType = RequestType.grant_role;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("targetAccount", account);
            params.put("roles", roles);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed grant role", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> grantRole(Session session, String account, Set<String> roles) {
        return asyncCall(() -> syncGrantRole(session, account, roles));
    }

    private OperationResult syncCreateUserAccount(Session session, String targetOrganization, String newAccount, String publicKey, Set<String> roles, boolean isSuperAdmin) {
        try {
            RequestType requestType = RequestType.create_user_account;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("targetOrganization", targetOrganization);
            params.put("targetAccount", newAccount);
            params.put("publicKey", publicKey);
            params.put("roles", String.join(" ", roles));
            params.put("isSuperAdmin", isSuperAdmin ? 1 : 0);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed create account", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> createUserAccount(Session session, String targetOrganization, String newAccount, String publicKey, Set<String> roles, boolean isSuperAdmin) {
        return asyncCall(() -> syncCreateUserAccount(session, targetOrganization, newAccount, publicKey, roles, isSuperAdmin));
    }

    private OperationResult syncResetConfig(Session session) {
        try {
            RequestType requestType = RequestType.reset_config;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            HttpReply reply = authPost(requestType, session, url, null, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed config reset", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> resetConfig(Session session) {
        return asyncCall(() -> syncResetConfig(session));
    }

    private OperationResult syncWithdraw(Session session, BigInteger amount) {
        try {
            RequestType requestType = RequestType.withdraw;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("amount", amount.toString());
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed withdraw", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> withdraw(Session session, String token, BigInteger amount) {
        return asyncCall(() -> syncWithdraw(session, amount));
    }

    private OperationResult syncWithdrawAuthorize(Session session, String token, String address) {
        try {
            String toSign = token + "\n" + address;
            String signature = KeysProvider.createAccountSignature(getApiContext().getSigPrivateKey(), toSign.getBytes(StandardCharsets.UTF_8));

            RequestType requestType = RequestType.withdraw_auth;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("address", address);
            params.put("signature", signature);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed withdraw authorize", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> withdrawAuthorize(Session session, String token, String address) {
        return asyncCall(() -> syncWithdrawAuthorize(session, token, address));
    }

    private OperationResult syncUploadApi(Session session, Map<String, Object> params) {
        try {
            RequestType requestType = RequestType.upload_api;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> request = new TreeMap<>();
            request.put("type", requestType.name());
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            if (params != null) {
                request.put("params", Utils.getGson().toJson(params));
            }
            HttpReply reply = authPost(requestType, session, url, request, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed retrieving upload API token", e);
            return new AccessError(null, e.toString());
        }
    }

    private OperationResult syncSetThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        try {
            RequestType requestType = RequestType.set_threshold_sig_pub_key;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> request = new TreeMap<>();
            request.put("type", requestType.name());
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            logger.debug("Sending set threshold sig pub key request");
            HttpReply reply = authPost(requestType, session, url, request, options != null ? options.getThresholdSigTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed set threshold sig pub key", e);
            return new AccessError(null, e.toString());
        }
    }

    public OperationResult syncReadThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        try {
            RequestType requestType = RequestType.read_threshold_sig_pub_key;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> request = new TreeMap<>();
            request.put("type", requestType.name());
            request.put("organization", session.getOrganization());
            request.put("account", session.getAccount());
            request.put("scope", scope);
            request.put("table", table);
            if (options != null) {
                request.put("options", Utils.getGson().toJson(options));
            }
            logger.debug("Sending read threshold sig pub key request");
            HttpReply reply = authPost(requestType, session, url, request, options != null ? options.getThresholdSigTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed read threshold sig pub key", e);
            return new AccessError(null, e.toString());
        }
    }

    private OperationResult syncThresholdSigPubkeyRound1(Session session, String scope, String table, String uuid, String message, ThresholdSigOptions options) {
        try {
            RequestType requestType = RequestType.threshold_sig_pubkey_round_1;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("type", requestType.name());
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            params.put("uuid", uuid);
            params.put("message", message);
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getThresholdSigTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed threshold sig round 1", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigPubkeyRound1(Session session, String scope, String table, String uuid, String message, ThresholdSigOptions options) {
        return asyncCall(() -> syncThresholdSigPubkeyRound1(session, scope, table, uuid, message, options));
    }

    private OperationResult syncThresholdSigRound2(Session session, String scope, String table, String uuid, String hash, byte[] scalarK, ThresholdSigOptions options) {
        try {
            RequestType requestType = RequestType.threshold_sig_round_2;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("type", requestType.name());
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("scope", scope);
            params.put("table", table);
            params.put("uuid", uuid);
            params.put("hash", hash);
            params.put("scalarK", Base58.encode(scalarK));
            if (options != null) {
                params.put("options", Utils.getGson().toJson(options));
            }
            HttpReply reply = authPost(requestType, session, url, params, options != null ? options.getThresholdSigTimeoutSec() : null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed threshold sig round 2", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> thresholdSigRound2(Session session, String scope, String table, String uuid, String message, byte[] scalarK, ThresholdSigOptions options) {
        return asyncCall(() -> syncThresholdSigRound2(session, scope, table, uuid, message, scalarK, options));
    }

    @Override
    public CompletableFuture<OperationResult> readThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        return asyncCall(() -> syncReadThresholdSigPubKey(session, scope, table, options));
    }

    @Override
    public CompletableFuture<OperationResult> setThresholdSigPubKey(Session session, String scope, String table, ThresholdSigOptions options) {
        return asyncCall(() -> syncSetThresholdSigPubKey(session, scope, table, options));
    }

    @Override
    public CompletableFuture<OperationResult> uploadApi(Session session, Map<String, Object> params) {
        return asyncCall(() -> syncUploadApi(session, params));
    }

    public OperationResult syncPeerStatus(Session session, List<String> queuedReplies) {
        try {
            RequestType requestType = RequestType.peer_status;
            String url = apiUrl + "/" + getClientVersion() + "/" + requestType.name();
            Map<String, Object> params = new HashMap<>();
            params.put("organization", session.getOrganization());
            params.put("account", session.getAccount());
            params.put("passive_replies", queuedReplies);
            HttpReply reply = authPost(requestType, session, url, params, null);
            return buildOperationResult(reply);
        } catch (Exception e) {
            logger.error("Failed status", e);
            return new AccessError(null, e.toString());
        }
    }

    @Override
    public CompletableFuture<OperationResult> peerStatus(Session session, List<String> queuedReplies) {
        return asyncCall(() -> syncPeerStatus(session, queuedReplies));
    }

    private OperationResult syncFile(String file, Consumer<byte[]> callback) {
        String url = apiUrl + "/" + RequestType.file.name() + "/" + file;

        HttpReply reply = httpTransport.syncDownload(url, DOWNLOAD_BUFFER_SIZE, callback);
        if (reply != null && reply.getStatusCode() == 200) {
            return new Success(null, reply.getBody());
        } else {
            return new AccessError(null, reply != null ? reply.getBody() : "No reply");
        }
    }

    @Override
    public CompletableFuture<OperationResult> file(String file, Consumer<byte[]> callback) {
        return asyncCall(() -> syncFile(file, callback));
    }
}
