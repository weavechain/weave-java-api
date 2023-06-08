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
public class MessageOptions {

    private int opTimeoutSec;

    private int ttlSec;

    public static class Serializer implements JsonSerializer<MessageOptions> {
        public JsonElement serialize(MessageOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("opTimeoutSec", new JsonPrimitive(data.getOpTimeoutSec()));
            element.add("ttlSec", new JsonPrimitive(data.getTtlSec()));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static MessageOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), MessageOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new MessageOptions(
                    ConvertUtils.convertToLong(data.get("opTimeoutSec"), (long)DEFAULT.getOpTimeoutSec()).intValue(),
                    ConvertUtils.convertToLong(data.get("ttlSec"), (long)DEFAULT.getTtlSec()).intValue()
            );
        } else {
            return MessageOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_OP_TIMEOUT_SEC = 300;

    public static final int DEFAULT_TIME_TO_LIVE_SEC = 300;

    public static MessageOptions DEFAULT = new MessageOptions(
            DEFAULT_OP_TIMEOUT_SEC,
            DEFAULT_TIME_TO_LIVE_SEC
    );
}