package com.weavechain.api.pre;

import com.weavechain.core.encoding.Utils;
import io.ipfs.multibase.Base58;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

@Getter
@AllArgsConstructor
public class ProxyEncryptedData {

    private final byte[] encoded;

    private final byte[] reencryptionKey;

    private final byte[] writerSignPubKey;

    private final byte[] readerPubKey;

    public String toJson() {
        Map<String, String> result = new HashMap<>();
        result.put("encoded", Base58.encode(encoded));
        result.put("reencryptionKey", Base58.encode(reencryptionKey));
        result.put("writerSignPubKey", Base58.encode(writerSignPubKey));
        result.put("readerPubKey", Base58.encode(readerPubKey));
        return Utils.getGson().toJson(result);
    }

    @SuppressWarnings("unchecked")
    public static ProxyEncryptedData fromJson(String data) {
        Map<String, String> items = (Map<String, String>)Utils.getGson().fromJson(data, Map.class);
        return new ProxyEncryptedData(
                Base58.decode(items.get("encoded")),
                Base58.decode(items.get("reencryptionKey")),
                Base58.decode(items.get("writerSignPubKey")),
                Base58.decode(items.get("readerPubKey"))
        );
    }
}
