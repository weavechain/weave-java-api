package com.weavechain.core.encoding;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.DataType;
import com.weavechain.core.data.Records;
import org.apache.commons.codec.binary.Base64;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class MsgPackContentEncoder implements ContentEncoder {

    public static final String TYPE = "mpack";

    static final Logger logger = LoggerFactory.getLogger(MsgPackContentEncoder.class);

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public String encode(Records data, DataLayout layout) {
        try {
            MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
            packer.packString(data.getTable());
            packer.packArrayHeader(data.getItems().size());
            for (List<Object> it : data.getItems()) {
                encodeRecord(packer, it, layout, null, layout.isAllowEndingNulls());
            }
            packer.close();

            //Ascii85.encode() - better for json, but slower, need a faster implementation before switching
            return Base64.encodeBase64String(packer.toMessageBuffer().toByteArray());
        } catch (IOException e) {
            logger.error("Failed packing", e);
            return null;
        }
    }

    public static void encodeRecord(MessageBufferPacker packer, List<Object> data, DataLayout layout, Integer exclude, boolean allowEndingNulls) throws IOException {
        for (int i = 0; i < layout.size(); i++) {
            if (exclude == null || !exclude.equals(i)) {
                DataType type = layout.getStorageType(i);

                Object obj;
                if (i >= data.size()) {
                    Object defaultValue = layout.getDefaultValue(i);
                    if (defaultValue != null) {
                        obj = defaultValue;
                    } else if (layout.getTimestampColumnIndex() != null && layout.getTimestampColumnIndex().equals(i)) {
                        obj = null;
                    } else if (allowEndingNulls) {
                        obj = null;
                    } else {
                        throw new IllegalArgumentException("Invalid record, missing column " + i);
                    }
                } else {
                    obj = data.get(i);
                }

                //TODO: workaround to keep NULL information
                if (DataType.LONG.equals(type)) {
                    if (obj != null) {
                        packer.packLong(ConvertUtils.convertToLong(obj));
                    } else {
                        packer.packLong(0L);
                    }
                } else if (DataType.DOUBLE.equals(type)) {
                    if (obj != null) {
                        packer.packDouble(ConvertUtils.convertToDouble(obj));
                    } else {
                        packer.packDouble(Double.NaN);
                    }
                } else if (DataType.TIMESTAMP.equals(type)) {
                    if (obj != null) {
                        packer.packString(ConvertUtils.convertToString(obj));
                    } else {
                        packer.packString("");
                    }
                } else if (DataType.STRING.equals(type)) {
                    if (obj != null) {
                        packer.packString(ConvertUtils.convertToString(obj));
                    } else {
                        packer.packString("");
                    }
                }
            }
        }
    }

    @Override
    public Records decode(String data, DataLayout layout) throws IOException {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(Base64.decodeBase64(data));
        String table = unpacker.unpackString();
        int size = unpacker.unpackArrayHeader();
        List<List<Object>> result = new ArrayList<>(size);
        for (int i = 0; i < size; ++i) {
            List<Object> items = decodeRecord(unpacker, layout, null);

            result.add(items);
        }
        unpacker.close();
        return new Records(table, result, data, TYPE);
    }

    public static List<Object> decodeRecord(MessageUnpacker unpacker, DataLayout layout, Integer exclude) throws IOException {
        List<Object> items = new ArrayList<>(2);

        for (int i = 0; i < layout.size(); i++) {
            if (exclude == null || !exclude.equals(i)) {
                DataType type = layout.getType(i);
                if (DataType.LONG.equals(type)) {
                    items.add(unpacker.unpackLong());
                } else if (DataType.DOUBLE.equals(type)) {
                    items.add(unpacker.unpackDouble());
                } else if (DataType.TIMESTAMP.equals(type)) {
                    items.add(unpacker.unpackString());
                } else if (DataType.STRING.equals(type)) {
                    items.add(unpacker.unpackString());
                }
            }
        }

        return items;
    }

    public static void packBytes(MessageBufferPacker packer, byte[] array) throws IOException {
        packer.packArrayHeader(array.length);
        for (byte b : array) {
            packer.packByte(b);
        }
    }

    public static byte[] unpackBytes(MessageUnpacker unpacker) throws IOException {
        int len = unpacker.unpackArrayHeader();
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = unpacker.unpackByte();
        }
        return result;
    }
}