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
public class DownloadOptions {

    public static final int ALL_ACTIVE = Integer.MAX_VALUE;

    private boolean verifyHash;

    private int readTimeoutSec;

    private int peersConsensus;

    private boolean enableMux;

    private boolean includeCached;

    private boolean stream;

    private String onBehalf;

    private String signature;

    private boolean verifySourceSignature;

    public ReadOptions toReadOptions() {
        return new ReadOptions(
                verifyHash,
                readTimeoutSec,
                peersConsensus,
                enableMux,
                includeCached,
                onBehalf,
                signature,
                verifySourceSignature,
                false,
                stream
        );
    }

    public static class Serializer implements JsonSerializer<DownloadOptions> {
        public JsonElement serialize(DownloadOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("verifyHash", new JsonPrimitive(data.isVerifyHash()));
            element.add("readTimeoutSec", new JsonPrimitive(data.getReadTimeoutSec()));
            element.add("peersConsensus", new JsonPrimitive(data.getPeersConsensus()));
            element.add("enableMux", new JsonPrimitive(data.isVerifyHash()));
            element.add("includeCached", new JsonPrimitive(data.isIncludeCached()));
            element.add("stream", new JsonPrimitive(data.isStream()));
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
    public static DownloadOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), DownloadOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new DownloadOptions(
                    ConvertUtils.convertToBoolean(data.get("verifyHash"), DEFAULT.isVerifyHash()),
                    ConvertUtils.convertToLong(data.get("readTimeoutSec"), (long)DEFAULT.getReadTimeoutSec()).intValue(),
                    ConvertUtils.convertToLong(data.get("peersConsensus"), (long)DEFAULT.getPeersConsensus()).intValue(),
                    ConvertUtils.convertToBoolean(data.get("enableMux"), DEFAULT.isVerifyHash()),
                    ConvertUtils.convertToBoolean(data.get("includeCached"), DEFAULT.isIncludeCached()),
                    ConvertUtils.convertToBoolean(data.get("stream"), DEFAULT.isStream()),
                    ConvertUtils.convertToString(data.get("onBehalf"), null),
                    ConvertUtils.convertToString(data.get("signature"), null),
                    ConvertUtils.convertToBoolean(data.get("verifySourceSignature"), DEFAULT.isVerifySourceSignature())
            );
        } else {
            return DownloadOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_READ_TIMEOUT_SEC = 300;

    public static DownloadOptions DEFAULT = new DownloadOptions(
            true,
            DEFAULT_READ_TIMEOUT_SEC,
            0,
            false,
            false,
            false,
            null,
            null,
            false
    );

    public static DownloadOptions DEFAULT_NO_CHAIN = new DownloadOptions(
            false,
            DEFAULT_READ_TIMEOUT_SEC,
            0,
            false,
            false,
            false,
            null,
            null,
            false
    );

    public static DownloadOptions DEFAULT_MUX = new DownloadOptions(
            true,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE,
            true,
            true,
            false,
            null,
            null,
            false
    );

    public static DownloadOptions DEFAULT_MUX_NO_CHAIN = new DownloadOptions(
            false,
            DEFAULT_READ_TIMEOUT_SEC,
            ALL_ACTIVE,
            true,
            true,
            false,
            null,
            null,
            false
    );
}