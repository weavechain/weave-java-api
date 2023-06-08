package com.weavechain.core.error;

import com.google.gson.*;
import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;

@Getter
@AllArgsConstructor
public class Raw implements OperationResult {

    @Getter
    OperationScope target;

    @Getter
    Object data;

    @Getter
    Integer statusCode;

    @Override
    public String getStringData() {
        return data instanceof String ? (String)data : Utils.getGson().toJson(data);
    }

    @Override
    public boolean isError() {
        return false;
    }

    @Override
    public String getMessage() {
        return null;
    }


    @Override
    public Object getMetadata() {
        return null;
    }

    @Override
    public String getStringMetadata() {
        return null;
    }

    @Override
    public String getIds() {
        return null;
    }

    @Override
    public String getHashes() {
        return null;
    }

    @Override
    public OperationResult toAuditRecord() {
        return null;
    }

    public static class Serializer implements JsonSerializer<Pending> {
        public JsonElement serialize(Pending data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("res", new JsonPrimitive(OperationResultSerializer.PENDING));
            if (data.getTarget() != null) {
                element.add("target", Utils.getGson().toJsonTree(data.getTarget()));
            }
            if (data.getData() != null) {
                element.add("data", new JsonPrimitive(data.getStringData()));
            }
            return element;
        }
    }
}