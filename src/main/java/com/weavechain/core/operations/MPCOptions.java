package com.weavechain.core.operations;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import com.google.gson.*;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.*;

@Getter
@AllArgsConstructor
public class MPCOptions {

    private static final String WILDCARD = "*";

    public static final List<String> ALL_ACTIVE_NODES = Collections.singletonList(WILDCARD);

    private boolean verifyHash;

    private int readTimeoutSec;

    private List<String> sources;

    private String transform;

    private String onBehalf;

    private String signature;

    private boolean verifySourceSignature;

    public boolean isAllActiveSources() {
        if (sources != null) {
            for (String src : sources) {
                if (WILDCARD.equals(src)) {
                    return true;
                }
            }
        }

        return false;
    }

    public static class Serializer implements JsonSerializer<MPCOptions> {
        public JsonElement serialize(MPCOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("verifyHash", new JsonPrimitive(data.isVerifyHash()));
            element.add("readTimeoutSec", new JsonPrimitive(data.getReadTimeoutSec()));
            JsonArray sources = new JsonArray(data.getSources() != null ? data.getSources().size() : 0);
            for (String item : data.getSources()) {
                sources.add(item);
            }
            element.add("sources", sources);
            element.add("transform", new JsonPrimitive(data.transform));
            if (data.onBehalf != null) {
                element.add("onBehalf", new JsonPrimitive(data.onBehalf));
            }
            if (data.signature != null) {
                element.add("signature", new JsonPrimitive(data.signature));
            }
            element.add("verifySourceSignature", new JsonPrimitive(data.isVerifySourceSignature()));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static MPCOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), MPCOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            List<String> sources = new ArrayList<>();
            if (data.get("sources") != null) {
                for (Object item : (Collection)data.get("sources")) {
                    sources.add(ConvertUtils.convertToString(item));
                }
            }
            return new MPCOptions(
                    ConvertUtils.convertToBoolean(data.get("verifyHash"), DEFAULT.isVerifyHash()),
                    ConvertUtils.convertToLong(data.get("readTimeoutSec"), (long)DEFAULT.getReadTimeoutSec()).intValue(),
                    sources,
                    ConvertUtils.convertToString(data.get("transform"), null),
                    ConvertUtils.convertToString(data.get("onBehalf"), null),
                    ConvertUtils.convertToString(data.get("signature"), null),
                    ConvertUtils.convertToBoolean(data.get("verifySourceSignature"), DEFAULT.isVerifySourceSignature())
                );
        } else {
            return MPCOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_READ_TIMEOUT_SEC = 300;

    public static MPCOptions DEFAULT = new MPCOptions(
            true,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE_NODES,
            null,
            null,
            null,
            false
    );

    public static MPCOptions DEFAULT_NO_CHAIN = new MPCOptions(
            false,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE_NODES,
            null,
            null,
            null,
            false
    );
}