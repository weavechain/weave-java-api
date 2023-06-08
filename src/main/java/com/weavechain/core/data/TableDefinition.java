package com.weavechain.core.data;

import com.google.gson.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.lang.reflect.Type;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class TableDefinition {

    public String field;

    public DataType dataType;

    public TableDefinition field(String value) {
        field = value;
        return this;
    }

    public TableDefinition dataType(DataType dataType) {
        this.dataType = dataType;
        return this;
    }

    public static class Serializer implements JsonSerializer<TableDefinition> {
        public JsonElement serialize(TableDefinition data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("name", new JsonPrimitive(data.getField()));
            element.add("columns", new JsonPrimitive(data.getDataType().name()));
            return element;
        }
    }
}