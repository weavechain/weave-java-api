package com.weavechain.core.encoding;

import com.squareup.moshi.JsonAdapter;
import com.squareup.moshi.JsonReader;
import com.squareup.moshi.JsonWriter;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.DataType;
import com.weavechain.core.data.Records;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class RecordsJSONAdapter extends JsonAdapter<Records> {
    private DataLayout dataLayout;

    public RecordsJSONAdapter withLayout(DataLayout dataLayout) {
        this.dataLayout = dataLayout;
        return this;
    }

    @Override
    public Records fromJson(JsonReader reader) throws IOException {
        reader.beginObject();

        String tableName = null;
        CopyOnWriteArrayList<Records.IntegrityPair> integrityPairs = null;
        List<List<Object>> items = null;
        String tag;

        do {
            tag = reader.nextName();
            if ("table".equals(tag)) {
                tableName = reader.nextString();
            } else if ("integrity".equals(tag)) {
                integrityPairs = readIntegrityPairs(reader);
            } else if ("items".equals(tag)) {
                items = readItems(reader);
            }
        } while (tag != null && reader.peek() != JsonReader.Token.END_OBJECT);

        reader.endObject();

        Records r =  new Records(tableName, items, null, null);
        r.setIntegrity(integrityPairs);
        return r;
    }

    @Override
    public void toJson(JsonWriter writer, Records records) throws IOException {
        writer.beginObject();

        // TABLE -------------------------------------------------------------------------
        writer.name("table");
        writer.value(records.getTable());

        // INTEGRITY ---------------------------------------------------------------------
        if (records.getIntegrity() != null) {
            writer.name("integrity");
            writer.beginArray();
            for (Records.IntegrityPair integrityPair : records.getIntegrity()) {
                writeIntegrityPairs(writer, integrityPair);
            }
            writer.endArray();
        }

        // ITEMS -------------------------------------------------------------------------
        writer.name("items");
        writer.beginArray();
        for (List<Object> record : records.getItems()) {
            writeRecord(writer, record);
        }
        writer.endArray();

        writer.endObject();
    }

    private List<List<Object>> readItems(JsonReader reader) throws IOException {
        List<List<Object>> result = new ArrayList<>();

        reader.beginArray();
        while (reader.hasNext()) {
            List<Object> item = new ArrayList<>();
            reader.beginArray();
            for (int i = 0; i < dataLayout.size(); i++) {
                if (reader.peek() == JsonReader.Token.NULL) {
                    item.add(reader.nextNull());
                } else if (dataLayout.getType(i).equals(DataType.LONG)) {
                    item.add(reader.nextLong());
                } else if (dataLayout.getType(i).equals(DataType.STRING)) {
                    item.add(reader.nextString());
                }
            }
            reader.endArray();

            result.add(item);
        }
        reader.endArray();
        return result;
    }

    private CopyOnWriteArrayList<Records.IntegrityPair> readIntegrityPairs(JsonReader reader) throws IOException {
        CopyOnWriteArrayList<Records.IntegrityPair> result = new CopyOnWriteArrayList<>();
        reader.beginArray();


        // add some king of loop to read all IntegrityPairs
        while (reader.hasNext()) {

            reader.beginObject();
            //TODO: this needs to be refactored, it's not ok to rely on position, need to go back an see why we needed the custom reader instead of using Gson
            String intervalStartWord = reader.nextName();
            int intervalStart = reader.nextInt();

            String signatureWord = reader.nextName();
            reader.beginObject();
            String sig = "";
            String pubKey = "";
            String recordsHash = "";
            String prevRecordsHash = null;
            String count = null;

            while (reader.hasNext()) {
                String signatureEntryName = reader.nextName();
                if ("recordsHash".equals(signatureEntryName)) {
                    recordsHash = reader.nextString();
                } else if ("prevRecordsHash".equals(signatureEntryName)) {
                    prevRecordsHash = reader.nextString();
                } else if ("pubKey".equals(signatureEntryName)) {
                    pubKey = reader.nextString();
                } else if ("sig".equals(signatureEntryName)) {
                    sig = reader.nextString();
                } else if ("count".equals(signatureEntryName)) {
                    count = reader.nextString();
                }
            }
            reader.endObject();

            Map<String, String> signature = new TreeMap<>();
            signature.put("sig", sig);
            signature.put("recordsHash", recordsHash);
            signature.put("pubKey", pubKey);
            if (prevRecordsHash != null) {
                signature.put("prevRecordsHash", prevRecordsHash);
            }
            if (count != null) {
                signature.put("count", count);
            }

            result.add(new Records.IntegrityPair(intervalStart, signature));
            reader.endObject();
        }
        reader.endArray();
        return result;
    }

    private void writeIntegrityPairs(JsonWriter writer, Records.IntegrityPair integrityPair) throws IOException {
        writer.beginObject();

        writer.name("intervalStart");
        writer.value(integrityPair.getIntervalStart());

        writer.name("sig"); //TODO: drop the need to have a list and a child "signature" element when only a single integrity signature (as it's the case from API clients)
        writer.beginObject();
        writer.name("sig");
        writer.value(integrityPair.getSignature().get("sig"));
        writer.name("recordsHash");
        writer.value(integrityPair.getSignature().get("recordsHash"));
        if (integrityPair.getSignature().get("prevRecordsHash") != null) {
            writer.name("prevRecordsHash");
            writer.value(integrityPair.getSignature().get("prevRecordsHash"));
        }
        writer.name("count");
        writer.value(integrityPair.getSignature().get("count"));
        writer.name("pubKey");
        writer.value(integrityPair.getSignature().get("pubKey"));
        writer.endObject();

        writer.endObject();
    }

    private void writeRecord(JsonWriter writer, List<Object> record) throws IOException {
        writer.beginArray();
        for (Object o : record) {
            if (o == null) {
                writer.nullValue();
            } else {
                if (o instanceof Double || o instanceof Float || o instanceof BigDecimal) {
                    writer.value(ConvertUtils.convertToDouble(o));
                } else if (o instanceof Number) {
                    writer.value(ConvertUtils.convertToLong(o));
                } else {
                    writer.value(ConvertUtils.convertToString(o));
                }
            }
        }
        writer.endArray();
    }

}
