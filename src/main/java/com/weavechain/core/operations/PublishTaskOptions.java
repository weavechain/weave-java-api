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
public class PublishTaskOptions {

    private int computeTimeoutSec;

    private Map<String, Object> params;

    private boolean allowCustomParams;

    public static class Serializer implements JsonSerializer<PublishTaskOptions> {
        public JsonElement serialize(PublishTaskOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("computeTimeoutSec", new JsonPrimitive(data.getComputeTimeoutSec()));
            if (data.getParams() != null) {
                element.add("params", new JsonPrimitive(Utils.getGson().toJson(data.getParams())));
            }
            element.add("allowCustomParams", new JsonPrimitive(data.isAllowCustomParams()));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static PublishTaskOptions fromObject(Object options) {
        if (options instanceof String) {
            try {
                return Utils.getGson().fromJson(options.toString(), PublishTaskOptions.class);
            } catch (Exception e) {
                return Utils.getGson().fromJson(Utils.getGson().fromJson(options.toString(), String.class), PublishTaskOptions.class);
            }
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new PublishTaskOptions(
                    ConvertUtils.convertToLong(data.get("computeTimeoutSec"), (long)DEFAULT.getComputeTimeoutSec()).intValue(),
                    data.get("params") != null ? Utils.getGson().fromJson(data.get("params").toString(), Map.class) : null,
                    ConvertUtils.convertToBoolean(data.get("allowCustomParams"), DEFAULT.isAllowCustomParams())
            );
        } else {
            return PublishTaskOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_COMPUTE_TIMEOUT_SEC = 600;

    public static PublishTaskOptions DEFAULT = new PublishTaskOptions(
            DEFAULT_COMPUTE_TIMEOUT_SEC,
            null,
            false
    );
}