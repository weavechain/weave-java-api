package com.weavechain.core.operations;

import com.google.gson.*;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;

@Getter
@AllArgsConstructor
public class PublishDatasetOptions {

    public static final int ALL_ACTIVE = Integer.MAX_VALUE;

    public static final String SNAPSHOT = "snapshot"; //data as at publish time, a snapshot is stored in the marketplace DB/file system

    public static final String LIVE_SNAPSHOT = "live"; //data as at download time, no snapshot is stored at publish time

    public static final String ROLLING = "rolling";

    public static final List<String> TYPES = List.of(
            SNAPSHOT,
            LIVE_SNAPSHOT,
            ROLLING
    );

    private String type;

    private String rollingUnit;

    private String rollingCount;

    private boolean verifyHash;

    private int readTimeoutSec;

    private int peersConsensus;

    private boolean enableMux;

    private boolean includeCached;

    private boolean verifySourceSignature;

    public static class Serializer implements JsonSerializer<PublishDatasetOptions> {
        public JsonElement serialize(PublishDatasetOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("type", new JsonPrimitive(data.getType()));
            element.add("rollingUnit", new JsonPrimitive(data.getRollingUnit()));
            element.add("rollingCount", new JsonPrimitive(data.getRollingCount()));
            element.add("verifyHash", new JsonPrimitive(data.isVerifyHash()));
            element.add("readTimeoutSec", new JsonPrimitive(data.getReadTimeoutSec()));
            element.add("peersConsensus", new JsonPrimitive(data.getPeersConsensus()));
            element.add("enableMux", new JsonPrimitive(data.isVerifyHash()));
            element.add("includeCached", new JsonPrimitive(data.isIncludeCached()));
            element.add("verifySourceSignature", new JsonPrimitive(data.isVerifySourceSignature()));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static PublishDatasetOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), PublishDatasetOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new PublishDatasetOptions(
                    ConvertUtils.convertToString(data.get("type"), DEFAULT.getType()),
                    ConvertUtils.convertToString(data.get("rollingUnit"), DEFAULT.getRollingUnit()),
                    ConvertUtils.convertToString(data.get("rollingCount"), DEFAULT.getRollingCount()),
                    ConvertUtils.convertToBoolean(data.get("verifyHash"), DEFAULT.isVerifyHash()),
                    ConvertUtils.convertToLong(data.get("readTimeoutSec"), (long)DEFAULT.getReadTimeoutSec()).intValue(),
                    ConvertUtils.convertToLong(data.get("peersConsensus"), (long)DEFAULT.getPeersConsensus()).intValue(),
                    ConvertUtils.convertToBoolean(data.get("enableMux"), DEFAULT.isVerifyHash()),
                    ConvertUtils.convertToBoolean(data.get("includeCached"), DEFAULT.isIncludeCached()),
                    ConvertUtils.convertToBoolean(data.get("verifySourceSignature"), DEFAULT.isVerifySourceSignature())
            );
        } else {
            return PublishDatasetOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_READ_TIMEOUT_SEC = 300;

    public static PublishDatasetOptions DEFAULT = new PublishDatasetOptions(
            SNAPSHOT,
            null,
            null,
            true,
            DEFAULT_READ_TIMEOUT_SEC,
            0,
            false,
            false,
            false
    );

    public static PublishDatasetOptions DEFAULT_NO_CHAIN = new PublishDatasetOptions(
            SNAPSHOT,
            null,
            null,
            false,
            DEFAULT_READ_TIMEOUT_SEC,
            0,
            false,
            false,
            false
    );

    public static PublishDatasetOptions DEFAULT_MUX = new PublishDatasetOptions(
            SNAPSHOT,
            null,
            null,
            true,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE,
            true,
            true,
            false
    );

    public static PublishDatasetOptions DEFAULT_MUX_NO_CHAIN = new PublishDatasetOptions(
            SNAPSHOT,
            null,
            null,
            false,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE,
            true,
            true,
            false
    );
}