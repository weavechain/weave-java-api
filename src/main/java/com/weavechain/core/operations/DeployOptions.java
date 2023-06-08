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
public class DeployOptions {

    private boolean sync;

    private int timeoutSec;

    private Map<String, Object> params;

    public static class Serializer implements JsonSerializer<DeployOptions> {
        public JsonElement serialize(DeployOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("sync", new JsonPrimitive(data.isSync()));
            element.add("timeoutSec", new JsonPrimitive(data.getTimeoutSec()));
            if (data.getParams() != null) {
                element.add("params", new JsonPrimitive(Utils.getGson().toJson(data.getParams())));
            }
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static DeployOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), DeployOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new DeployOptions(
                    ConvertUtils.convertToBoolean(data.get("sync"), DEFAULT.isSync()),
                    ConvertUtils.convertToLong(data.get("timeoutSec"), (long)DEFAULT.getTimeoutSec()).intValue(),
                    data.get("params") != null ? Utils.getGson().fromJson(data.get("params").toString(), Map.class) : null
            );
        } else {
            return DeployOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_COMPUTE_TIMEOUT_SEC = 300;

    public static final int DEFAULT_MAX_BATCH_SIZE = 1;

    public static DeployOptions DEFAULT = new DeployOptions(
            false,
            DEFAULT_COMPUTE_TIMEOUT_SEC,
            null
    );
}