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
public class ComputeOptions {

    public static final int ALL_ACTIVE_PEERS = Integer.MAX_VALUE;

    private boolean sync;

    private int timeoutSec;

    private int peersConsensus;

    private String scopes; //needed only when using consensus

    private Map<String, Object> params;

    private String onBehalf;

    private String signature;

    public static class Serializer implements JsonSerializer<ComputeOptions> {
        public JsonElement serialize(ComputeOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("sync", new JsonPrimitive(data.isSync()));
            element.add("timeoutSec", new JsonPrimitive(data.getTimeoutSec()));
            element.add("peersConsensus", new JsonPrimitive(data.getPeersConsensus()));
            element.add("scopes", new JsonPrimitive(data.getScopes()));
            if (data.getParams() != null) {
                element.add("params", new JsonPrimitive(Utils.getGson().toJson(data.getParams())));
            }
            if (data.onBehalf != null) {
                element.add("onBehalf", new JsonPrimitive(data.onBehalf));
            }
            if (data.signature != null) {
                element.add("signature", new JsonPrimitive(data.signature));
            }
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static ComputeOptions fromObject(Object options) {
        if (options instanceof String) {
            return ComputeOptions.fromObject(Utils.getGson().fromJson((String)options, Map.class));
        } else if (options instanceof Map) {
            Map data = (Map)options;

            Map params;
            if (data.get("params") instanceof Map) {
                params = (Map)data.get("params");
            } else if (data.get("params") != null) {
                try {
                    params = Utils.getGson().fromJson(data.get("params").toString(), Map.class);
                } catch (Exception e) {
                    params = Utils.getGson().fromJson(Utils.getGson().fromJson(data.get("params").toString(), String.class), Map.class);
                }
            } else {
                params = null;
            }

            return new ComputeOptions(
                    ConvertUtils.convertToBoolean(data.get("sync"), DEFAULT.isSync()),
                    ConvertUtils.convertToLong(data.get("timeoutSec"), (long)DEFAULT.getTimeoutSec()).intValue(),
                    ConvertUtils.convertToLong(data.get("peersConsensus"), (long)DEFAULT.getPeersConsensus()).intValue(),
                    ConvertUtils.convertToString(data.get("scopes"), DEFAULT.getScopes()),
                    params,
                    ConvertUtils.convertToString(data.get("onBehalf"), null),
                    ConvertUtils.convertToString(data.get("signature"), null)
            );
        } else {
            return ComputeOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_COMPUTE_TIMEOUT_SEC = 300;

    public static final int DEFAULT_MAX_BATCH_SIZE = 1;

    public static ComputeOptions DEFAULT = new ComputeOptions(
            false,
            DEFAULT_COMPUTE_TIMEOUT_SEC,
            0,
            null,
            null,
            null,
            null
    );
}