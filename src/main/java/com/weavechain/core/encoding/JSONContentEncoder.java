package com.weavechain.core.encoding;

import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.Records;

import java.io.IOException;
import java.util.List;

public class JSONContentEncoder implements ContentEncoder {

    public static final String TYPE  = "json";

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public String encode(Records data, DataLayout layout) {
        return Utils.getRecordsJsonAdapter(layout).toJson(data);
    }

    @Override
    public Records decode(String data, DataLayout layout) throws IOException {
        Records result;
        try {
            result = Utils.getRecordsJsonAdapter(layout).fromJson(data);
        } catch (Exception e) {
            try {
                result = Utils.getGson().fromJson(data, Records.class);
            } catch (Exception ex) {
                List<Object> items = Utils.getGson().fromJson(data, List.class);
                result = new Records("", Records.buildItems(layout, items), data, TYPE);
            }
        }

        if (result != null) {
            result.setEncoding(TYPE);
            result.setSerialization(data);
        }
        return result;
    }
}