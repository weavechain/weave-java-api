package com.weavechain.core.operations;

import com.google.gson.*;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;

@Getter
@AllArgsConstructor
public class ChainOptions {

    private int opTimeoutSec;

    public static class Serializer implements JsonSerializer<ChainOptions> {
        public JsonElement serialize(ChainOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("opTimeoutSec", new JsonPrimitive(data.getOpTimeoutSec()));
            return element;
        }
    }

    public static final int DEFAULT_OP_TIMEOUT_SEC = 300;

    public static ChainOptions DEFAULT = new ChainOptions(
            DEFAULT_OP_TIMEOUT_SEC
    );
}