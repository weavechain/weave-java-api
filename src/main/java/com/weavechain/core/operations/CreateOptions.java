package com.weavechain.core.operations;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.encoding.Utils;
import com.google.gson.*;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.Map;

@Getter
@AllArgsConstructor
public class CreateOptions {

    public static final int DEFAULT_TIMEOUT_SEC = 60;

    public static final int PEER_CREATE_TIMEOUT_SEC = 10;

    public static CreateOptions DEFAULT = new CreateOptions(true, true, null, DEFAULT_TIMEOUT_SEC);

    public static CreateOptions FAILSAFE = new CreateOptions(false, true, null, DEFAULT_TIMEOUT_SEC);

    private boolean failIfExists;

    private boolean replicate;

    private DataLayout layout;

    private Integer createTimeoutSec;

    public CreateOptions(boolean failIfExists) {
        this(failIfExists, true, null, DEFAULT_TIMEOUT_SEC);
    }

    public static class Serializer implements JsonSerializer<CreateOptions> {
        public JsonElement serialize(CreateOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("failIfExists", new JsonPrimitive(data.isFailIfExists()));
            element.add("replicate", new JsonPrimitive(data.isReplicate()));
            if (data.getLayout() != null) {
                element.add("layout", Utils.getGson().toJsonTree(data.getLayout()));
            }
            element.add("timeoutSec", new JsonPrimitive(data.getCreateTimeoutSec() != null ? data.getCreateTimeoutSec() : DEFAULT_TIMEOUT_SEC));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static CreateOptions fromObject(Object options) {
        if (options instanceof String) {
            try {
                return Utils.getGson().fromJson(options.toString(), CreateOptions.class);
            } catch (Exception e) {
                //try simplified parsing
                Map<String, Object> data = Utils.getGson().fromJson(options.toString(), Map.class);
                Boolean failIfExists = ConvertUtils.convertToBoolean(data.get("failIfExists"));
                Boolean replicate = ConvertUtils.convertToBoolean(data.get("replicate"), true);
                DataLayout layout = DataLayout.unpackLayout(data);
                Integer timeoutSec = ConvertUtils.convertToInteger(data.get("timeoutSec"), DEFAULT_TIMEOUT_SEC);

                return new CreateOptions(failIfExists, replicate, layout, timeoutSec);
            }
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new CreateOptions(
                    ConvertUtils.convertToBoolean(data.get("failIfExists"), DEFAULT.isFailIfExists()),
                    ConvertUtils.convertToBoolean(data.get("replicate"), DEFAULT.isReplicate()),
                    Utils.getGson().fromJson((JsonElement)data.get("layout"), DataLayout.class),
                    ConvertUtils.convertToInteger(data.get("timeoutSec"), DEFAULT.getCreateTimeoutSec())
            );
        } else {
            return CreateOptions.DEFAULT;
        }
    }
}