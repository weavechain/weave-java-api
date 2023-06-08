package com.weavechain.core.encoding;

import lombok.Getter;

public class Encoding {

    @Getter
    private static final ContentEncoder msgPackContentEncoder = new MsgPackContentEncoder();

    @Getter
    private static final ContentEncoder jsonContentEncoder = new JSONContentEncoder();

    //TODO: protobuf
    //TODO: consider adding a gzip layer here

    public static ContentEncoder getDefaultContentEncoder() {
        return jsonContentEncoder;
    }

    public static ContentEncoder getContentEncoder(String type) {
        if (JSONContentEncoder.TYPE.equals(type)) {
            return jsonContentEncoder;
        } else if (MsgPackContentEncoder.TYPE.equals(type)) {
            return msgPackContentEncoder;
        } else {
            return getDefaultContentEncoder();
        }
    }
}