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
public class SplitLearnOptions {

    private static final String WILDCARD = "*";

    public static final List<String> ALL_ACTIVE_NODES = Collections.singletonList(WILDCARD);

    private boolean sync;

    private int timeoutSec;

    private int minParticipants;

    private String scopes; //needed only when using consensus

    private List<String> sources;

    private Map<String, Object> params;

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

    public static class Serializer implements JsonSerializer<SplitLearnOptions> {
        public JsonElement serialize(SplitLearnOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("sync", new JsonPrimitive(data.isSync()));
            element.add("timeoutSec", new JsonPrimitive(data.getTimeoutSec()));
            element.add("minParticipants", new JsonPrimitive(data.getMinParticipants()));
            element.add("scopes", new JsonPrimitive(data.getScopes()));
            JsonArray sources = new JsonArray(data.getSources() != null ? data.getSources().size() : 0);
            for (String item : data.getSources()) {
                sources.add(item);
            }
            element.add("sources", sources);
            if (data.getParams() != null) {
                element.add("params", new JsonPrimitive(Utils.getGson().toJson(data.getParams())));
            }
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static SplitLearnOptions fromObject(Object options) {
        if (options instanceof String) {
            return SplitLearnOptions.fromObject(Utils.getGson().fromJson(options.toString(), Map.class));
        } else if (options instanceof Map) {
            Map data = (Map) options;
            List<String> sources = new ArrayList<>();
            if (data.get("sources") != null) {
                for (Object item : (Collection) data.get("sources")) {
                    sources.add(ConvertUtils.convertToString(item));
                }
            }
            return new SplitLearnOptions(
                    ConvertUtils.convertToBoolean(data.get("sync"), DEFAULT.isSync()),
                    ConvertUtils.convertToLong(data.get("timeoutSec"), (long)DEFAULT.getTimeoutSec()).intValue(),
                    ConvertUtils.convertToLong(data.get("minParticipants"), (long)DEFAULT.minParticipants).intValue(),
                    ConvertUtils.convertToString(data.get("scopes"), DEFAULT.getScopes()),
                    sources,
                    data.get("params") != null ? Utils.getGson().fromJson(data.get("params").toString(), Map.class) : null
            );
        } else {
            return SplitLearnOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_SL_TIMEOUT_SEC = 300;

    public static final int DEFAULT_MAX_BATCH_SIZE = 1;

    public static SplitLearnOptions DEFAULT = new SplitLearnOptions(
            false,
            DEFAULT_SL_TIMEOUT_SEC,
            0,
            null,
            ALL_ACTIVE_NODES,
            null
    );
}