package com.weavechain.core.operations;

import com.google.gson.*;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.Map;

@Getter
@AllArgsConstructor
public class FLOptions {

    private boolean sync;

    private int timeoutSec;

    private int peersConsensus;

    private String scopes; //needed only when using consensus

    private Map<String, Object> params;

    public static class Serializer implements JsonSerializer<FLOptions> {
        public JsonElement serialize(FLOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("sync", new JsonPrimitive(data.isSync()));
            element.add("timeoutSec", new JsonPrimitive(data.getTimeoutSec()));
            element.add("peersConsensus", new JsonPrimitive(data.getPeersConsensus()));
            element.add("scopes", new JsonPrimitive(data.getScopes()));
            if (data.getParams() != null) {
                element.add("params", new JsonPrimitive(Utils.getGson().toJson(data.getParams())));
            }
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static FLOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), FLOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new FLOptions(
                    ConvertUtils.convertToBoolean(data.get("sync"), DEFAULT.isSync()),
                    ConvertUtils.convertToLong(data.get("timeoutSec"), (long)DEFAULT.getTimeoutSec()).intValue(),
                    ConvertUtils.convertToLong(data.get("peersConsensus"), (long)DEFAULT.getPeersConsensus()).intValue(),
                    ConvertUtils.convertToString(data.get("scopes"), DEFAULT.getScopes()),
                    data.get("params") != null ? Utils.getGson().fromJson(data.get("params").toString(), Map.class) : null
            );
        } else {
            return FLOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_FL_TIMEOUT_SEC = 300;

    public static final int DEFAULT_MAX_BATCH_SIZE = 1;

    public static FLOptions DEFAULT = new FLOptions(
            false,
            DEFAULT_FL_TIMEOUT_SEC,
            0,
            null,
            null
    );
}