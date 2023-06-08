package com.weavechain.core.data;

import com.weavechain.core.encoding.Utils;
import com.google.gson.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.lang.reflect.Type;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class TableColumn {

    public String name;

    public List<TableColumn> columns;

    public TableColumn name(String value) {
        name = value;
        return this;
    }

    public TableColumn columns(List<TableColumn> values) {
        this.columns = values;
        return this;
    }

    public static class Serializer implements JsonSerializer<TableColumn> {
        public JsonElement serialize(TableColumn data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("name", new JsonPrimitive(data.getName()));
            element.add("columns", Utils.getGson().toJsonTree(data.getColumns()));
            return element;
        }
    }
}