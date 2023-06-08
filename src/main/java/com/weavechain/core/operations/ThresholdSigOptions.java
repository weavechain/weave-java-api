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
public class ThresholdSigOptions {

    private int thresholdSigTimeoutSec;

    public static class Serializer implements JsonSerializer<ThresholdSigOptions> {
        public JsonElement serialize(ThresholdSigOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("thresholdSigTimeoutSec", new JsonPrimitive(data.getThresholdSigTimeoutSec()));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static ThresholdSigOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), ThresholdSigOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map) options;
            return new ThresholdSigOptions(
                    ConvertUtils.convertToLong(data.get("thresholdSigTimeoutSec"), (long) DEFAULT.getThresholdSigTimeoutSec()).intValue());
        } else {
            return ThresholdSigOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_THRESHOLD_SIG_TIMEOUT_SEC = 300;

    public static ThresholdSigOptions DEFAULT = new ThresholdSigOptions(
            DEFAULT_THRESHOLD_SIG_TIMEOUT_SEC
    );
}
