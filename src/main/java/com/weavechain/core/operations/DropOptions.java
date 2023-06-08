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
public class DropOptions {

    public static final int DEFAULT_TIMEOUT_SEC = 60;

    public static final int PEER_DROP_TIMEOUT_SEC = 10;

    public static DropOptions DEFAULT = new DropOptions(true, false, DEFAULT_TIMEOUT_SEC);

    public static DropOptions FAILSAFE = new DropOptions(false, false, DEFAULT_TIMEOUT_SEC);

    private boolean failIfNotExists;

    private boolean replicate;

    private Integer dropTimeoutSec;

    public DropOptions(boolean failIfNotExists) {
        this(failIfNotExists, true, DEFAULT_TIMEOUT_SEC);
    }

    public static class Serializer implements JsonSerializer<DropOptions> {
        public JsonElement serialize(DropOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("failIfNotExists", new JsonPrimitive(data.isFailIfNotExists()));
            element.add("replicate", new JsonPrimitive(data.isReplicate()));
            element.add("timeoutSec", new JsonPrimitive(data.getDropTimeoutSec() != null ? data.getDropTimeoutSec() : DEFAULT_TIMEOUT_SEC));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static DropOptions fromObject(Object options) {
        if (options instanceof String) {
            try {
                return Utils.getGson().fromJson(options.toString(), DropOptions.class);
            } catch (Exception e) {
                //try simplified parsing
                Map<String, Object> data = Utils.getGson().fromJson(options.toString(), Map.class);
                Boolean failIfNotExists = ConvertUtils.convertToBoolean(data.get("failIfNotExists"));
                Boolean replicate = ConvertUtils.convertToBoolean(data.get("replicate"), true);
                Integer timeoutSec = ConvertUtils.convertToInteger(data.get("timeoutSec"), DEFAULT_TIMEOUT_SEC);

                return new DropOptions(failIfNotExists, replicate, timeoutSec);
            }
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new DropOptions(
                    ConvertUtils.convertToBoolean(data.get("failIfNotExists"), DEFAULT.isFailIfNotExists()),
                    ConvertUtils.convertToBoolean(data.get("replicate"), DEFAULT.isReplicate()),
                    ConvertUtils.convertToInteger(data.get("timeoutSec"), DEFAULT.getDropTimeoutSec())
            );
        } else {
            return DropOptions.DEFAULT;
        }
    }
}