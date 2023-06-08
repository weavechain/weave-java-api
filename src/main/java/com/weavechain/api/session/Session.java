package com.weavechain.api.session;

import com.weavechain.api.ApiContext;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.KeyExchange;
import com.weavechain.core.encrypt.KeysProvider;
import io.ipfs.multibase.binary.Base64;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

@Getter
@AllArgsConstructor
public class Session {

    public static long DEFAULT_KEY_DURATION_SEC = 24L * 3600; //TODO: move to config

    public static int DEFAULT_EXPIRY_CUSHION_SEC = 10;

    private String organization;

    private String account;

    private String publicKey;

    private String scopes;

    private String apiKey;

    private String secret;

    private Long secretExpireUTC;

    private String authorizedDomain;

    private AtomicLong nonce;

    private String proxyNode;

    private String tempKey;

    private Boolean integrityChecks;

    private int expiryCushionSec = DEFAULT_EXPIRY_CUSHION_SEC;

    private final transient Map<String, PrevRecordsData> prevRecordsData = Utils.newConcurrentHashMap();

    public boolean isExpired() {
        return secretExpireUTC != null && secretExpireUTC < Instant.now().getEpochSecond();
    }

    public boolean nearExpiry() {
        return secretExpireUTC != null && secretExpireUTC < Instant.now().getEpochSecond() + expiryCushionSec;
    }

    public PrevRecordsData getPrevRecordsData(String scope, String table) {
        String key = scope + ":" + table;
        return prevRecordsData.get(key);
    }

    public PrevRecordsData setPrevRecordsData(String scope, String table, String hash, Integer count) {
        String key = scope + ":" + table;
        return prevRecordsData.put(key, new PrevRecordsData(hash, count));
    }

    @SuppressWarnings("unchecked")
    public static Session parse(Object source, ApiContext apiContext) {
        if (source == null) {
            return null;
        }

        Map<String, Object> reply = source instanceof Map ? (Map)source : Utils.getGson().fromJson(source.toString(), Map.class);

        String node = reply.get("x-src") != null ? reply.get("x-src").toString() : null;
        KeyExchange keyExchange = KeysProvider.getInstance();
        PublicKey srvPublicKey = node != null
                ? keyExchange.readKeys(null, node).getPublic()
                : apiContext.getServerPublicKey();

        byte[] kmsg = reply.get("x-kmsg") != null ? Base64.decodeBase64(reply.get("x-kmsg").toString()) : null;
        SecretKey secretKey = keyExchange.sharedSecret(apiContext.getClientPrivateKey(), srvPublicKey, kmsg);

        byte[] iv = Hex.decode(reply.get("x-iv").toString());
        byte[] secretBytes = keyExchange.decrypt(secretKey, Hex.decode(((String)reply.get("secret"))), apiContext.getSeed(), iv);
        String secret = new String(secretBytes, StandardCharsets.UTF_8);

        return new Session(
                (String)reply.get("organization"),
                (String)reply.get("account"),
                (String)reply.get("publicKey"),
                (String)reply.get("scopes"),
                (String)reply.get("apiKey"),
                secret,
                ConvertUtils.convertToLong(reply.get("secretExpireUTC")),
                (String)reply.get("authorizedDomain"),
                new AtomicLong(0L),
                node,
                (String)reply.get("x-pk"),
                ConvertUtils.convertToBoolean(reply.get("integrityChecks")),
                DEFAULT_EXPIRY_CUSHION_SEC
        );
    }

    @Getter
    @AllArgsConstructor
    public static class PrevRecordsData {

        private final String hash;

        private final Integer count;
    }
}