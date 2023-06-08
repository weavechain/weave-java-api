package com.weavechain.core.data;

import com.google.gson.*;
import com.weavechain.core.encoding.ContentEncoder;
import com.weavechain.core.encoding.Utils;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.*;

@Getter
@NoArgsConstructor
public class Records {

    static final Logger logger = LoggerFactory.getLogger(Records.class);

    public String table;

    private List<List<Object>> items;

    @Setter
    private transient String serialization;

    @Setter
    private transient String encoding;

    @Setter
    private List<IntegrityPair> integrity = null;

    public Records(String table, List<List<Object>> items, String serialization, String encoding) {
        this.table = table;
        this.items = items;
        this.serialization = serialization;
        this.encoding = encoding;
    }

    public static class IntegrityPair {
        /** A Records object can contain merged data from many parts, where all parts have their signature
         * A Records object holds an ordered list of IntegrityPairs (ordered by intervalStart)
         * Each IntegrityPair contains the signature for interval
         * Records.items.get(intervalStart_current) -> Records.items.get(intervalStart_next - 1) */
        private final Integer intervalStart;

        private final Map<String, String> sig = new TreeMap<>();

        public int getIntervalStart() {
            return intervalStart != null ? intervalStart : 0;
        }

        public Map<String, String> getSignature() {
            return sig;
        }

        public IntegrityPair(int intervalStart, Map<String, String> sig) {
            this.intervalStart = intervalStart;
            this.sig.putAll(sig);
        }
    }

    public static Object getRecordId(List<Object> item, DataLayout layout) {
        //TODO: Review, we need to unify with getLongRecordId and keep dual support for string ids (with limited functionality when hashing to smart contracts)
        Integer idx = layout.getIdColumnIndex();
        try {
            if (idx != null) {
                return item.size() > idx ? ConvertUtils.convertToLong(item.get(idx)) : null;
            } else {
                Integer idxTs = layout.getTimestampColumnIndex();
                return idxTs != null && item.size() > idxTs ? ConvertUtils.convertToLong(item.get(idxTs)) : null;
            }
        } catch (Exception e) {
            if (idx != null) {
                return item.size() > idx ? item.get(idx) : null;
            } else {
                Integer idxTs = layout.getTimestampColumnIndex();
                return idxTs != null && item.size() > idxTs ? item.get(idxTs) : null;
            }
        }
    }

    public static Long getLongRecordId(List<Object> item, DataLayout layout) {
        //TODO: Review, we need to unify with getRecordId and keep dual support for string ids (with limited functionality when hashing to smart contracts)
        Integer idx = layout.getIdColumnIndex();
        if (idx != null) {
            return item.size() > idx ? ConvertUtils.convertToLong(item.get(idx)) : null;
        } else {
            Integer idxTs = layout.getTimestampColumnIndex();
            return idxTs != null && item.size() > idxTs ? ConvertUtils.convertToLong(item.get(idxTs)) : null;
        }
    }

    public static void standardize(List<Object> record, DataLayout layout) {
        //make sure the write and read order and representation are the same when serializing
        for (int i = 0; i < layout.size(); i++) {
            if (i < record.size()) {
                Object conv = ConvertUtils.convert(record.get(i), layout.getType(i));
                if (conv instanceof Double && conv.toString().endsWith(".0")) {
                    conv = ((Double)conv).longValue(); //remove ending .0 from serializations
                }
                record.set(i, conv);
            } else {
                record.add(null);
            }
        }

        if (layout.getSignatureColumnIndex() != null && "".equals(record.get(layout.getSignatureColumnIndex()))) {
            record.set(layout.getSignatureColumnIndex(), null);

        }
    }

    public static List<Object> standardizeWithoutOwner(List<Object> record, DataLayout layout) {
        List<Object> result = new ArrayList<>();
        for (int i = 0; i < layout.size(); i++) {
            if (layout.getOwnerColumnIndex() != null && layout.getOwnerColumnIndex() == i
                    || layout.getSignatureColumnIndex() != null && layout.getSignatureColumnIndex() == i
                    || layout.getSourceIpColumnIndex() != null && layout.getSourceIpColumnIndex() == i
                    || layout.getEncryptSaltColumnIndex() != null && layout.getEncryptSaltColumnIndex() == i
            ) {
                while (result.size() <= i) {
                    result.add(null);
                }
            } else {
                Object conv;
                try {
                    conv = ConvertUtils.convert(record.get(i), layout.getType(i));
                    if (conv instanceof Double && conv.toString().endsWith(".0")) {
                        conv = ((Double) conv).longValue(); //remove ending .0 from serializations
                    }
                } catch (Exception e) {
                    logger.trace("Failed converting, fallback to original value", e);
                    conv = record.get(i) != null ? record.get(i).toString() : null;
                }

                if (i < result.size()) {
                    result.add(i, conv);
                } else {
                    while (result.size() < i) {
                        result.add(null);
                    }
                    result.add(conv);
                }
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> recordToList(Object record, DataLayout layout) {
        if (record instanceof Map) {
            List<Object> result = new ArrayList<>();
            Map<String, Object> item = (Map<String, Object>)record;
            for (int i = 0; i < layout.size(); i++) {
                result.add(item.get(layout.getColumn(i)));
            }
            return result;
        } else {
            return (List<Object>)record;
        }
    }

    public static Records of(String table, List<Object>... items) {
        return new Records(table, Arrays.asList(items), null, null);
    }

    public static Records of(String table, List<List<Object>> items) {
        return new Records(table, items, null, null);
    }

    public static Records ofMap(String table, List<String> columns, DataLayout layout, Object... items) {
        return new Records(table, buildItems(columns, layout, items), null, null);
    }

    public static Records ofRow(String table, DataLayout layout, Object item) {
        return new Records(table, buildItems(layout, Collections.singletonList(item)), null, null);
    }

    public static Records ofRows(String table, DataLayout layout, List<?> items) {
        return new Records(table, buildItems(layout, items), null, null);
    }

    public static List<List<Object>> buildItems(DataLayout layout, Object... items) {
        return buildItems(null, layout, items);
    }

    @SuppressWarnings("unchecked")
    public static List<List<Object>> buildItems(List<String> columns, DataLayout layout, Object... items) {
        List<List<Object>> result = new ArrayList<>();
        for (Object data : items) {
            if (data == null) {
                continue;
            }

            Set<String> colsWithFailure = new HashSet<>();

            for (Object item : (List)data) {
                if (item instanceof List) {
                    result.add((List<Object>) item);
                } else if (item instanceof Map) {
                    Map<String, Object> it = (Map) item;

                    DataLayout tableLayout = layout != null ? layout : DataLayout.DEFAULT;
                    List<Object> row = new ArrayList<>();
                    for (int i = 0; i < tableLayout.size(); i++) {
                        String column = tableLayout.getColumn(i);
                        if (columns != null && columns.size() > 0 && !columns.contains(column)) {
                            continue;
                        }

                        DataType type = tableLayout.getType(i);
                        Object value = it.get(column);
                        try {
                            row.add(ConvertUtils.convert(value, type));
                        } catch (Exception e) {
                            if (!colsWithFailure.contains(column)) {
                                logger.warn("Failed converting value column " + column + " to " + type.name() + ", using original");
                                colsWithFailure.add(column);
                            }
                            row.add(value);
                        }
                    }

                    result.add(row);
                } else {
                    logger.error("Unhandled record type");
                }
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public static Records fromObject(Object records, ContentEncoder encoder, DataLayout layout) {
        if (records instanceof String) {
            try {
                return encoder.decode(records.toString(), layout);
            } catch (IOException e) {
                logger.error("Failed parsing records", e);
                return null;
            }
        } else if (records instanceof Map) {
            Map data = (Map)records;
            return new Records(
                    ConvertUtils.convertToString(data.get("table")),
                    (List)data.get("items"),
                    null,
                    null
            );
        } else {
            return null;
        }
    }

    public void applyTimestamp(Long now, DataLayout layout, boolean keepIfExists) {
        Integer idx = layout.getTimestampColumnIndex();
        if (idx != null) {
            for (List<Object> record : items) {
                int size = record.size();
                if (idx < size && (!keepIfExists || record.get(idx) == null)) {
                    if (record.get(idx) == null) {
                        record.set(idx, now);
                    }
                } else if (idx >= size) {
                    for (int j = 0; j < idx - size; j++) {
                        record.add(null);
                    }
                    record.add(now);
                }
            }
        }
    }

    public String toJson(DataLayout layout) {
        if (items != null) {
            List<Map<String, Object>> data = new ArrayList<>();
            for (List<Object> it : items) {
                Map<String, Object> row = new LinkedHashMap<>();
                for (int i = 0; i < layout.size(); i++) {
                    row.put(layout.getColumn(i), i < it.size() ? it.get(i) : null);
                }
                data.add(row);
            }
            return Utils.getGson().toJson(data);
        } else {
            return null;
        }
    }

    public static class Serializer implements JsonSerializer<Records> {
        public JsonElement serialize(Records data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("table", new JsonPrimitive(data.getTable()));
            element.add("items", Utils.getGson().toJsonTree(data.getItems()).getAsJsonArray());
            return element;
        }
    }
}