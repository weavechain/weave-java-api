package com.weavechain.core.operations;

import com.google.gson.*;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.file.FileFormat;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.Map;

@Getter
@AllArgsConstructor
public class OutputOptions {

    private String format;

    public static class Serializer implements JsonSerializer<OutputOptions> {
        public JsonElement serialize(OutputOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("format", new JsonPrimitive(data.getFormat()));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static OutputOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), OutputOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new OutputOptions(
                    ConvertUtils.convertToString(data.get("format"), DEFAULT.getFormat())
            );
        } else {
            return OutputOptions.DEFAULT;
        }
    }

    public static OutputOptions CSV = new OutputOptions(
            FileFormat.csv.name()
    );

    public static OutputOptions DEFAULT = CSV;
}