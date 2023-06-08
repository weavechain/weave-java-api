package com.weavechain.api.pre;

import com.weavechain.core.encoding.Utils;
import io.ipfs.multibase.Base58;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

@Getter
@AllArgsConstructor
public class ClientEncryptedData {

    private final byte[] encoded;

    private final byte[] proxySignPubKey;

    public String toJson() {
        Map<String, String> result = new HashMap<>();
        result.put("encoded", Base58.encode(encoded));
        result.put("proxySignPubKey", Base58.encode(proxySignPubKey));
        return Utils.getGson().toJson(result);
    }

    @SuppressWarnings("unchecked")
    public static ClientEncryptedData fromJson(String data) {
        Map<String, String> items = (Map<String, String>)Utils.getGson().fromJson(data, Map.class);
        return new ClientEncryptedData(
                Base58.decode(items.get("encoded")),
                Base58.decode(items.get("proxySignPubKey"))
        );
    }
}
