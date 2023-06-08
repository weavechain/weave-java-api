package com.weavechain.core.error;

import com.weavechain.core.audit.AuditUtils;
import com.weavechain.core.encoding.Utils;
import com.google.gson.*;
import com.weavechain.core.operations.ApiOperationType;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

@Getter
@AllArgsConstructor
public class Success implements OperationResult {

    OperationScope target;

    Object data;

    Object metadata;

    String ids;

    String hashes;

    public Success(OperationScope target, Object data) {
        this(target, data, null, null, null);
    }

    public Success(OperationScope target, Object data, Object metadata) {
        this(target, data, metadata, null, null);
    }

    @Override
    public String getStringData() {
        return data instanceof String ? (String)data : Utils.getGson().toJson(data);
    }

    @Override
    public String getStringMetadata() {
        return metadata instanceof String ? (String)metadata : Utils.getGson().toJson(metadata);
    }

    @Override
    public boolean isError() {
        return false;
    }

    @Override
    public String getMessage() {
        return OperationResultSerializer.SUCCESS;
    }

    public String getHashes() {
        return hashes;
    }

    @Override
    public OperationResult toAuditRecord() {
        if (AuditUtils.LOG_DATA) {
            return new Success(target,
                    data instanceof String
                            ? ((String) data).length() > AuditUtils.MAX_LOGGED_SIZE ? ((String) data).substring(0, AuditUtils.MAX_LOGGED_SIZE) + "..." : (String)data
                    : data instanceof List
                            ? ((List) data).size() > AuditUtils.MAX_LOGGED_COUNT ? ((List) data).subList(0, AuditUtils.MAX_LOGGED_COUNT) : (List)data
                    : data,
                    metadata, ids, hashes);
        } if (target != null && (
                ApiOperationType.READ.equals(target.getOperationType())
                || ApiOperationType.VERIFY.equals(target.getOperationType())
                || ApiOperationType.SUBSCRIBE.equals(target.getOperationType())
                || ApiOperationType.DOWNLOAD.equals(target.getOperationType())
        )) {
            return new Success(target, null, metadata, ids, hashes);
        } else {
            return new Success(target, null, metadata, ids, hashes);
        }
    }

    public static class Serializer implements JsonSerializer<Success> {
        public JsonElement serialize(Success data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("res", new JsonPrimitive(OperationResultSerializer.SUCCESS));
            if (data.getTarget() != null) {
                element.add("target", Utils.getGson().toJsonTree(data.getTarget()));
            }
            if (data.getData() != null) {
                serialize(element, "data", data.getData(), data::getStringData);
            }
            if (data.getMetadata() != null) {
                serialize(element, "metadata", data.getMetadata(), data::getStringMetadata);
            }
            if (data.getIds() != null) {
                element.add("ids", new JsonPrimitive(data.getIds()));
            }
            if (data.getHashes() != null) {
                element.add("hashes", new JsonPrimitive(data.getHashes()));
            }
            return element;
        }

        private void serialize(JsonObject element, String name, Object data, Supplier<String> stringData) {
            if (data instanceof List) {
                element.add(name, Utils.getGson().toJsonTree(data).getAsJsonArray());
            } else if (data instanceof Map) {
                element.add(name, Utils.getGson().toJsonTree(data).getAsJsonObject());
            } else {
                element.add(name, new JsonPrimitive(stringData.get()));
            }
        }
    }
}