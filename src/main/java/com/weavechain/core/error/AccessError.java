package com.weavechain.core.error;

import com.weavechain.core.encoding.Utils;
import com.google.gson.*;
import lombok.Getter;

import java.lang.reflect.Type;

@Getter
public class AccessError extends Error {

    OperationScope target;

    String message;

    public AccessError(OperationScope target, String message) {
        this.target = target;
        this.message = message;
    }

    public static class Serializer implements JsonSerializer<AccessError> {
        public JsonElement serialize(AccessError data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("res", new JsonPrimitive(OperationResultSerializer.ERR));
            if (data.getTarget() != null) {
                element.add("target", Utils.getGson().toJsonTree(data.getTarget()));
            }
            if (data.getMessage() != null) {
                element.add("message", new JsonPrimitive(data.getMessage()));
            }
            return element;
        }
    }
}