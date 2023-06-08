package com.weavechain.core.error;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;

import java.util.Map;

public class OperationResultSerializer {

    public static final String ERR = "err";

    public static final String SUCCESS = "ok";

    public static final String PENDING = "pend";

    public static final String FWD = "fwd";

    public static OperationResult from(Object data) {
        try {
            Map items = data != null ? (data instanceof Map ? (Map) data : Utils.getGson().fromJson(data.toString(), Map.class)) : null;
            if (data == null) {
                return new AccessError(null, "No result");
            } else if (ERR.equals(items.get("res"))) {
                return new AccessError(null, (String) items.get("message"));
            } else if (FWD.equals(items.get("res"))) {
                return new Forward(null, items.get("data"), false);
            } else {
                return new Success(
                        OperationScope.from(items.get("target")),
                        items.get("data"),
                        items.get("metadata"),
                        (String) items.get("ids"),
                        (String) items.get("hashes")
                );
            }
        } catch (Exception e) {
            //TODO: maybe log the exception? could generate too much logging in cases like webserver 500 failures
            return new AccessError(null, ConvertUtils.convertToString(data));
        }
    }
}