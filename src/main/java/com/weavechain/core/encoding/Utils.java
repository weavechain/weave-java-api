package com.weavechain.core.encoding;

import cafe.cryptography.curve25519.Scalar;
import com.google.gson.*;
import com.squareup.moshi.JsonAdapter;
import com.squareup.moshi.Moshi;
import com.weavechain.core.consensus.ConsensusMessage;
import com.weavechain.core.data.*;
import com.weavechain.core.encrypt.HashFunction;
import com.weavechain.core.encrypt.HashSHA3;
import com.weavechain.core.error.AccessError;
import com.weavechain.core.error.Forward;
import com.weavechain.core.error.Success;
import com.weavechain.core.operations.CreateOptions;
import com.weavechain.core.operations.WriteOptions;
import org.bitcoinj.base.Base58;
import org.bouncycastle.jcajce.provider.digest.SHA3;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

public class Utils {

    private static final int DEFAULT_INITIAL_CAPACITY = 4;
    private static final float DEFAULT_LOAD_FACTOR = 0.9f;
    private static final int CONCURRENT_UPDATE_THREADS =  1;

    public static <K, V> ConcurrentHashMap<K, V> newConcurrentHashMap() {
        return new ConcurrentHashMap<>(DEFAULT_INITIAL_CAPACITY, DEFAULT_LOAD_FACTOR, CONCURRENT_UPDATE_THREADS);
    }

    private static final ThreadLocal<Gson> gson = ThreadLocal.withInitial(Utils::createGson);

    private static final ThreadLocal<HashFunction> didHash = ThreadLocal.withInitial(() -> new HashSHA3(SHA3.Digest256::new));

    public static Gson getGson() {
        return gson.get();
    }

    private static final ThreadLocal<RecordsJSONAdapter> recordsJsonAdapter = ThreadLocal.withInitial(RecordsJSONAdapter::new);
    public static JsonAdapter<Records> getRecordsJsonAdapter(DataLayout layout) {
        return recordsJsonAdapter.get().withLayout(layout);
    }

    private static final ThreadLocal<JsonAdapter<WriteOptions>> optionsJsonAdapter = ThreadLocal.withInitial(() -> new Moshi.Builder().build().adapter(WriteOptions.class));
    public static JsonAdapter<WriteOptions> getWriteOptionsJsonAdapter() {
        return optionsJsonAdapter.get();
    }

    private static final ThreadLocal<JsonAdapter<Map>> mapJsonAdapter = ThreadLocal.withInitial(() -> new Moshi.Builder().build().adapter(Map.class));
    public static JsonAdapter<Map> getMapJsonAdapter() {
        return mapJsonAdapter.get();
    }

    private static final ThreadLocal<JsonAdapter<List>> listJsonAdapter = ThreadLocal.withInitial(() -> new Moshi.Builder().build().adapter(List.class));
    public static JsonAdapter<List> getListJsonAdapter() {
        return listJsonAdapter.get();
    }

    private static final ThreadLocal<JsonAdapter<ConsensusMessage>> messageJsonAdapter = ThreadLocal.withInitial(() -> new Moshi.Builder().build().adapter(ConsensusMessage.class));
    public static JsonAdapter<ConsensusMessage> getMessageJsonAdapter() {
        return messageJsonAdapter.get();
    }

    public static GsonBuilder createGsonBuilder() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.setLongSerializationPolicy(LongSerializationPolicy.STRING);
        gsonBuilder.setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE);
        gsonBuilder.registerTypeAdapter(Records.class, new Records.Serializer());
        gsonBuilder.registerTypeAdapter(Scalar.class, new ScalarSerializer());
        gsonBuilder.registerTypeAdapter(TableDefinition.class, new TableDefinition.Serializer());
        gsonBuilder.registerTypeAdapter(TableColumn.class, new TableColumn.Serializer());
        gsonBuilder.registerTypeAdapter(WriteOptions.class, new WriteOptions.Serializer());
        gsonBuilder.registerTypeAdapter(CreateOptions.class, new CreateOptions.Serializer());
        gsonBuilder.registerTypeAdapter(Success.class, new Success.Serializer());
        gsonBuilder.registerTypeAdapter(Forward.class, new Forward.Serializer());
        gsonBuilder.registerTypeAdapter(AccessError.class, new AccessError.Serializer());
        gsonBuilder.disableHtmlEscaping();
        return gsonBuilder
                .serializeSpecialFloatingPointValues();
    }

    public static Gson createGson() {
        return createGsonBuilder()
                .create();
    }

    public static class ScalarSerializer implements JsonSerializer<Scalar>, JsonDeserializer<Scalar> {
        public JsonElement serialize(Scalar data, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(Base58.encode(data.toByteArray()));
        }

        public Scalar deserialize(JsonElement json, Type typeOfSrc, JsonDeserializationContext context) {
            return Scalar.fromBits(Base58.decode(json.getAsString()));
        }
    }

    public static String escapeFormat(String s) {
        return s.replaceAll("%", "");
    }

    public static String escapeEnvString(String s) {
        return s
                .replaceAll("`", "")
                .replaceAll("\\{", "")
                .replaceAll("}", "")
                .replaceAll("\\$", "");
    }

    public static String getDataToSign(Map<String, Object> data) {
        //return Utils.getMapJsonAdapter().toJson(data);

        StringBuilder builder = new StringBuilder();

        builder.append(data.get("x-api-key"));
        builder.append("\n");
        builder.append(data.get("nonce"));
        builder.append("\n");
        builder.append(data.get("signature"));
        builder.append("\n");
        builder.append(data.get("organization"));
        builder.append("\n");
        builder.append(data.get("account"));
        builder.append("\n");
        builder.append(data.get("scope"));
        builder.append("\n");
        builder.append(data.get("table"));
        //builder.append("\n");
        //builder.append(data.get("records"));

        return builder.toString();
    }

    public static String generateDID(String ownerKey, Map<String, Object> data) {
        String content = Utils.getGson().toJson(new TreeMap<>(data));
        return generateDID(ownerKey, content);
    }

    public static String generateDID(String ownerKey, String data) {
        String hash = didHash.get().b58Digest(data);
        return generateDIDFromHash(ownerKey, hash);
    }

    public static String generateDIDFromHash(String ownerKey, String dataHash) {
        String owner = ownerKey.substring("weave".length());
        return "did:weave:" + owner + ":" + dataHash;
    }

    public static String generateUUID() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    public static String sanitizePath(String path) {
        return path;
    }

    public static String sanitizeSQL(String value) {
        return value == null ? "" : value
                .replaceAll("\\\\", "\\\\\\\\")
                .replaceAll(";", "")
                .replaceAll("`", "")
                .replaceAll(",", "")
                .replaceAll("#", "")
                .replaceAll("'", "\\\\\'");
    }


    public static Boolean isRunningInsideDocker() {
        try (Stream<String> stream = Files.lines(Paths.get("/proc/1/cgroup"))) {
            return stream.anyMatch(line -> line.contains("/docker"));
        } catch (Exception e) {
            return false;
        }
    }

    public static String getDefaultGateway() {
        try {
            Process console = Runtime.getRuntime().exec("netstat -rn");
            BufferedReader output = new BufferedReader(new InputStreamReader(console.getInputStream()));

            boolean readNext = false;
            String line = output.readLine();
            while (line != null) {
                if (line.contains("Gateway")) {
                    readNext = true;
                } else if (readNext) {
                    StringTokenizer st = new StringTokenizer(line);
                    String first = st.nextToken();
                    String second = st.nextToken();
                    String third = st.nextToken();
                    String gateway = !"default".equals(second) && !"0.0.0.0".equals(second) ? second : third;
                    return gateway;
                }

                line = output.readLine();
            }

            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static String getLocalHost() {
        String host;
        try {
            host = Inet4Address.getLocalHost().getHostAddress();
        } catch (Exception e) {
            return "localhost";
        }
        return host;
    }

    public static boolean isUnix() {
        String os = System.getProperty("os.name").toLowerCase();
        return os.contains("nix") || os.contains("nux") || os.contains("aix");
    }

    public static String getUsedHost() {
        String os = System.getProperty("os.name");
        if (os != null && (os.toLowerCase(Locale.ROOT).contains("windows")
                || os.toLowerCase(Locale.ROOT).contains("darwin")
                || os.toLowerCase(Locale.ROOT).contains("mac"))) {
            //could be used also for windows if we start the docker image with --add-host host.docker.internal:host-gateway
            return "host.docker.internal";
        } else {
            return getLocalHost();
        }
    }

    private static boolean hasHostDockerInternal() {
        String os = System.getProperty("os.name");
        return os != null && (os.toLowerCase(Locale.ROOT).contains("windows")
                || os.toLowerCase(Locale.ROOT).contains("darwin")
                || os.toLowerCase(Locale.ROOT).contains("mac"));
    }

    private static String getGatewayAddress() {
        try {
            if (hasHostDockerInternal()) {
                //could be used also for windows if we start the docker image with --add-host host.docker.internal:host-gateway
                return "host.docker.internal";
            } else {
                String gw = getDefaultGateway();
                if (gw != null) {
                    return gw;
                } else {
                    String localHost = Inet4Address.getLocalHost().getHostAddress();
                    if (localHost.startsWith("172.")) {
                        int idx = localHost.lastIndexOf(".");
                        return localHost.substring(0, idx + 1) + "1";
                    } else {
                        return "172.17.0.1";
                    }
                }
            }
        } catch (Exception e) {
            return null;
        }
    }

    public static String parseHost(String host) {
        try {
            String address = InetAddress.getByName(host).getHostAddress();
            return host; //intentionally returning the original address, we just make sure the address can be solved
        } catch (Exception e) {
            if (isRunningInsideDocker() && "gw".equals(host)) {
                return getGatewayAddress();
            } else {
                return host;
            }
        }
    }
}