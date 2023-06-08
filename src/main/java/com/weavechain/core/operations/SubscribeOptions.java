package com.weavechain.core.operations;

import com.google.gson.*;
import com.weavechain.core.batching.BatchingOptions;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.Map;

@Getter
@AllArgsConstructor
public class SubscribeOptions {

    private boolean verifyHash;

    private boolean initialSnapshot;

    private int readTimeoutSec;

    private boolean externalUpdates;

    private BatchingOptions batchingOptions;

    //TODO: operators that can be combined:
    //      dplyr style (mutate, select, filter, summarize, arrange, group_by)
    //      or js style (foreach, map, reduce, filter, concat, join), maybe arrange, distinct, collapse

    public static class Serializer implements JsonSerializer<SubscribeOptions> {
        public JsonElement serialize(SubscribeOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("verifyHash", new JsonPrimitive(data.isVerifyHash()));
            element.add("initialSnapshot", new JsonPrimitive(data.isInitialSnapshot()));
            element.add("readTimeoutSec", new JsonPrimitive(data.getReadTimeoutSec()));
            element.add("externalUpdates", new JsonPrimitive(data.isExternalUpdates()));
            if (data.batchingOptions != null) {
                element.add("batchingOptions", new JsonPrimitive(data.batchingOptions.toJson()));
            }
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static SubscribeOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), SubscribeOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new SubscribeOptions(
                    ConvertUtils.convertToBoolean(data.get("verifyHash"), DEFAULT.isVerifyHash()),
                    ConvertUtils.convertToBoolean(data.get("initialSnapshot"), DEFAULT.isInitialSnapshot()),
                    ConvertUtils.convertToLong(data.get("readTimeoutSec"), (long)DEFAULT.getReadTimeoutSec()).intValue(),
                    ConvertUtils.convertToBoolean(data.get("externalUpdates"), DEFAULT.isVerifyHash()),
                    BatchingOptions.fromJson(data.get("batchingOptions"), BatchingOptions.DEFAULT_BATCHING)
            );
        } else {
            return SubscribeOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_SUBSCRIBE_TIMEOUT_SEC = 300;

    public static final int DEFAULT_MAX_BATCH_SIZE = 1;

    public static SubscribeOptions DEFAULT = new SubscribeOptions(
            true,
            true,
            DEFAULT_SUBSCRIBE_TIMEOUT_SEC,
            false,
            BatchingOptions.DEFAULT_BATCHING
    );

    public static SubscribeOptions DEFAULT_NO_BATCHING = new SubscribeOptions(
            true,
            true,
            DEFAULT_SUBSCRIBE_TIMEOUT_SEC,
            false,
            BatchingOptions.DEFAULT_NO_BATCHING
    );

    public static SubscribeOptions DEFAULT_NO_CHAIN = new SubscribeOptions(
            false,
            true,
            DEFAULT_SUBSCRIBE_TIMEOUT_SEC,
            false,
            BatchingOptions.DEFAULT_BATCHING
    );

    public static SubscribeOptions DEFAULT_NO_CHAIN_NO_BATCHING = new SubscribeOptions(
            false,
            true,
            DEFAULT_SUBSCRIBE_TIMEOUT_SEC,
            false,
            BatchingOptions.DEFAULT_NO_BATCHING
    );
}