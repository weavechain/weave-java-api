package com.weavechain.core.operations;

import com.google.gson.*;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.*;

@Getter
@AllArgsConstructor
public class ZKOptions {

    private static final String WILDCARD = "*";

    public static final List<String> ALL_ACTIVE_NODES = Collections.singletonList(WILDCARD);

    private boolean verifyHash;

    private int readTimeoutSec;

    private List<String> sources;

    private int generators;

    private String commitment; //32 bytes, base58 encoded

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

    public static class Serializer implements JsonSerializer<ZKOptions> {
        public JsonElement serialize(ZKOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("verifyHash", new JsonPrimitive(data.isVerifyHash()));
            element.add("readTimeoutSec", new JsonPrimitive(data.getReadTimeoutSec()));
            JsonArray sources = new JsonArray(data.getSources() != null ? data.getSources().size() : 0);
            for (String item : data.getSources()) {
                sources.add(item);
            }
            element.add("sources", sources);
            element.add("generators", new JsonPrimitive(data.getGenerators()));
            element.add("commitment", new JsonPrimitive(data.getGenerators()));
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
    public static ZKOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), ZKOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            List<String> sources = new ArrayList<>();
            if (data.get("sources") != null) {
                for (Object item : (Collection)data.get("sources")) {
                    sources.add(ConvertUtils.convertToString(item));
                }
            }
            return new ZKOptions(
                    ConvertUtils.convertToBoolean(data.get("verifyHash"), DEFAULT.isVerifyHash()),
                    ConvertUtils.convertToLong(data.get("readTimeoutSec"), (long)DEFAULT.getReadTimeoutSec()).intValue(),
                    sources,
                    ConvertUtils.convertToInteger(data.get("generators"), DEFAULT.getGenerators()),
                    ConvertUtils.convertToString(data.get("commitment")),
                    ConvertUtils.convertToString(data.get("onBehalf"), null),
                    ConvertUtils.convertToString(data.get("signature"), null),
                    ConvertUtils.convertToBoolean(data.get("verifySourceSignature"), DEFAULT.isVerifySourceSignature())
                );
        } else {
            return ZKOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_READ_TIMEOUT_SEC = 300;

    public static final int DEFAULT_GENERATORS = 128;

    public static final String DEFAULT_COMMITMENT = "GGumV86X6FZzHRo8bLvbW2LJ3PZ45EqRPWeogP8ufcm3";

    public static ZKOptions DEFAULT = new ZKOptions(
            true,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE_NODES,
            DEFAULT_GENERATORS,
            DEFAULT_COMMITMENT,
            null,
            null,
            false
    );

    public static ZKOptions DEFAULT_NO_CHAIN = new ZKOptions(
            false,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE_NODES,
            DEFAULT_GENERATORS,
            DEFAULT_COMMITMENT,
            null,
            null,
            false
    );
}