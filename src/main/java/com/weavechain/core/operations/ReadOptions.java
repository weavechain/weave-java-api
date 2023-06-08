package com.weavechain.core.operations;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import com.google.gson.*;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.Map;

@Getter
@AllArgsConstructor
public class ReadOptions {

    public static final int ALL_ACTIVE = Integer.MAX_VALUE;

    private boolean verifyHash;

    private int readTimeoutSec;

    private int peersConsensus;

    private boolean enableMux;

    private boolean includeCached;

    private String onBehalf;

    private String signature;

    private boolean verifySourceSignature;

    private boolean getBatchHashes;

    private boolean stream;

    public static class Serializer implements JsonSerializer<ReadOptions> {
        public JsonElement serialize(ReadOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("verifyHash", new JsonPrimitive(data.isVerifyHash()));
            element.add("readTimeoutSec", new JsonPrimitive(data.getReadTimeoutSec()));
            element.add("peersConsensus", new JsonPrimitive(data.getPeersConsensus()));
            element.add("enableMux", new JsonPrimitive(data.isVerifyHash()));
            element.add("includeCached", new JsonPrimitive(data.isIncludeCached()));
            if (data.onBehalf != null) {
                element.add("onBehalf", new JsonPrimitive(data.onBehalf));
            }
            if (data.signature != null) {
                element.add("signature", new JsonPrimitive(data.signature));
            }
            element.add("verifySourceSignature", new JsonPrimitive(data.isVerifySourceSignature()));
            element.add("getBatchHashes", new JsonPrimitive(data.isGetBatchHashes()));
            element.add("stream", new JsonPrimitive(data.isStream()));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static ReadOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), ReadOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new ReadOptions(
                    ConvertUtils.convertToBoolean(data.get("verifyHash"), DEFAULT.isVerifyHash()),
                    ConvertUtils.convertToLong(data.get("readTimeoutSec"), (long)DEFAULT.getReadTimeoutSec()).intValue(),
                    ConvertUtils.convertToLong(data.get("peersConsensus"), (long)DEFAULT.getPeersConsensus()).intValue(),
                    ConvertUtils.convertToBoolean(data.get("enableMux"), DEFAULT.isVerifyHash()),
                    ConvertUtils.convertToBoolean(data.get("includeCached"), DEFAULT.isIncludeCached()),
                    ConvertUtils.convertToString(data.get("onBehalf"), null),
                    ConvertUtils.convertToString(data.get("signature"), null),
                    ConvertUtils.convertToBoolean(data.get("verifySourceSignature"), DEFAULT.isVerifySourceSignature()),
                    ConvertUtils.convertToBoolean(data.get("getBatchHashes"), DEFAULT.isGetBatchHashes()),
                    ConvertUtils.convertToBoolean(data.get("stream"), DEFAULT.isStream())
            );
        } else {
            return ReadOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_READ_TIMEOUT_SEC = 300;

    public static ReadOptions DEFAULT = new ReadOptions(
            true,
            DEFAULT_READ_TIMEOUT_SEC,
            0,
            false,
            false,
            null,
            null,
            false,
            false,
            false
    );

    public static ReadOptions DEFAULT_NO_CHAIN = new ReadOptions(
            false,
            DEFAULT_READ_TIMEOUT_SEC,
            0,
            false,
            false,
            null,
            null,
            false, //TODO: evaluate having this to true by default. If done, change also in MPCOptions, ZKOptions, PublishOptions (and in the other language APIs)
            false,
            false
    );

    public static ReadOptions DEFAULT_MUX = new ReadOptions(
            true,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE,
            true,
            true,
            null,
            null,
            false,
             false,
            false
    );

    public static ReadOptions DEFAULT_MUX_NO_CHAIN = new ReadOptions(
            false,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE,
            true,
            true,
            null,
            null,
            false,
            false,
            false
    );
}