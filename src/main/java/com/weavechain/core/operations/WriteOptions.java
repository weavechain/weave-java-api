package com.weavechain.core.operations;

import com.weavechain.core.batching.BatchingOptions;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import com.google.gson.*;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.Map;

@Getter
@EqualsAndHashCode
@AllArgsConstructor
public class WriteOptions {

    private boolean guaranteed;

    private int minAcks;

    private boolean inMemoryAcks;

    private int minHashAcks;

    private int writeTimeoutSec;

    private boolean allowDistribute;

    private boolean signOnChain; //TODO: dangerous to have this option. remove?

    private boolean syncSigning;

    private boolean allowRemoteBatching; //TODO: Reevaluate. This can create nondeterministic batches on receiving nodes (depending when they get the package)

    private boolean allowLocalBatching;

    private BatchingOptions batchingOptions;

    private String correlationUuid;

    private String onBehalf;

    private String signature;

    public int getMinAcks() {
        return allowDistribute ? minAcks : 1;
    }

    public static class Serializer implements JsonSerializer<WriteOptions> {
        public JsonElement serialize(WriteOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("guaranteed", new JsonPrimitive(data.isGuaranteed()));
            element.add("minAcks", new JsonPrimitive(data.getMinAcks()));
            element.add("inMemoryAcks", new JsonPrimitive(data.isInMemoryAcks()));
            element.add("minHashAcks", new JsonPrimitive(data.getMinHashAcks()));
            element.add("writeTimeoutSec", new JsonPrimitive(data.getWriteTimeoutSec()));
            element.add("allowDistribute", new JsonPrimitive(data.isAllowDistribute()));
            element.add("signOnChain", new JsonPrimitive(data.isSignOnChain()));
            element.add("syncSigning", new JsonPrimitive(data.isSyncSigning()));
            element.add("allowRemoteBatching", new JsonPrimitive(data.isAllowRemoteBatching()));
            element.add("allowLocalBatching", new JsonPrimitive(data.isAllowLocalBatching()));
            if (data.batchingOptions != null) {
                element.add("batchingOptions", new JsonPrimitive(data.batchingOptions.toJson()));
            }
            if (data.correlationUuid != null) {
                element.add("uuid", new JsonPrimitive(data.correlationUuid));
            }
            if (data.onBehalf != null) {
                element.add("onBehalf", new JsonPrimitive(data.onBehalf));
            }
            if (data.signature != null) {
                element.add("signature", new JsonPrimitive(data.signature));
            }
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static WriteOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), WriteOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new WriteOptions(
                    ConvertUtils.convertToBoolean(data.get("guaranteed"), DEFAULT.isGuaranteed()),
                    ConvertUtils.convertToLong(data.get("minAcks"), (long)DEFAULT.getMinAcks()).intValue(),
                    ConvertUtils.convertToBoolean(data.get("inMemoryAcks"), DEFAULT.isInMemoryAcks()),
                    ConvertUtils.convertToLong(data.get("minHashAcks"), (long)DEFAULT.getMinHashAcks()).intValue(),
                    ConvertUtils.convertToLong(data.get("writeTimeoutSec"), (long)DEFAULT.getWriteTimeoutSec()).intValue(),
                    ConvertUtils.convertToBoolean(data.get("allowDistribute"), DEFAULT.isAllowDistribute()),
                    ConvertUtils.convertToBoolean(data.get("signOnChain"), DEFAULT.isSignOnChain()),
                    ConvertUtils.convertToBoolean(data.get("syncSigning"), DEFAULT.isSyncSigning()),
                    ConvertUtils.convertToBoolean(data.get("allowRemoteBatching"), DEFAULT.isAllowRemoteBatching()),
                    ConvertUtils.convertToBoolean(data.get("allowLocalBatching"), DEFAULT.isAllowLocalBatching()),
                    BatchingOptions.fromJson(data.get("batchingOptions"), BatchingOptions.DEFAULT_BATCHING),
                    ConvertUtils.convertToString(data.get("uuid"), null),
                    ConvertUtils.convertToString(data.get("onBehalf"), null),
                    ConvertUtils.convertToString(data.get("signature"), null)
            );
        } else {
            return WriteOptions.DEFAULT;
        }
    }

    public static boolean DEFAULT_GUARANTEED_DELIVERY = true;

    public static int DEFAULT_MIN_ACKS = 1;

    public static boolean DEFAULT_MEMORY_ACKS = false;

    public static int DEFAULT_HASH_ACKS = 1;

    public static final int DEFAULT_WRITE_TIMEOUT_SEC = 300;

    public static WriteOptions DEFAULT = new WriteOptions(
            DEFAULT_GUARANTEED_DELIVERY,
            DEFAULT_MIN_ACKS,
            DEFAULT_MEMORY_ACKS,
            DEFAULT_HASH_ACKS,
            DEFAULT_WRITE_TIMEOUT_SEC,
            true,
            true,
            true,
            false,
            false,
            BatchingOptions.DEFAULT_BATCHING,
            null,
            null,
            null
    );

    public static WriteOptions DEFAULT_ASYNC = new WriteOptions(
            false,
            DEFAULT_MIN_ACKS,
            true,
            0,
            DEFAULT_WRITE_TIMEOUT_SEC,
            true,
            true,
            true,
            false,
            false,
            BatchingOptions.DEFAULT_BATCHING,
            null,
            null,
            null
    );

    public static WriteOptions DEFAULT_NO_CHAIN = new WriteOptions(
            DEFAULT_GUARANTEED_DELIVERY,
            DEFAULT_MIN_ACKS,
            DEFAULT_MEMORY_ACKS,
            0,
            DEFAULT_WRITE_TIMEOUT_SEC,
            true,
            false,
            true,
            false,
            false,
            BatchingOptions.DEFAULT_BATCHING,
            null,
            null,
            null
    );
}