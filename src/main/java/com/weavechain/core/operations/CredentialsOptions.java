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
public class CredentialsOptions {

    public static final String JSON_LD = "json-ld";

    public static final String JWT = "jwt";

    private int opTimeoutSec;

    private String proofType;

    private Long expirationTimestampGMT;

    public static class Serializer implements JsonSerializer<CredentialsOptions> {
        public JsonElement serialize(CredentialsOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("opTimeoutSec", new JsonPrimitive(data.getOpTimeoutSec()));
            element.add("proofType", new JsonPrimitive(data.getProofType()));
            if (data.getExpirationTimestampGMT() != null) {
                element.add("expirationTimestampGMT", new JsonPrimitive(data.getExpirationTimestampGMT()));
            }
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static CredentialsOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), CredentialsOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new CredentialsOptions(
                    ConvertUtils.convertToLong(data.get("opTimeoutSec"), (long)DEFAULT.getOpTimeoutSec()).intValue(),
                    ConvertUtils.convertToString(data.get("proofType"), DEFAULT.getProofType()),
                    ConvertUtils.convertToLong(data.get("expirationTimestampGMT"), null)
            );
        } else {
            return CredentialsOptions.DEFAULT;
        }
    }

    public static final int DEFAULT_OP_TIMEOUT_SEC = 300;

    public static CredentialsOptions DEFAULT = new CredentialsOptions(
            DEFAULT_OP_TIMEOUT_SEC,
            JSON_LD,
            null
    );
}