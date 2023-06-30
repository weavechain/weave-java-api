package com.weavechain.core.data.transform;

import com.weavechain.core.data.DataLayout;
import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Map;

public class Redaction implements Transformation {

    @Override
    public Object transform(String scope, String table, Object value) {
        TransformationAlgoParams algoParams = DataLayout.getTransformAlgoParams(scope, table);
        Redaction.Params params = algoParams != null ? algoParams.getRedactionParams() : null;

        if (value == null) {
            return null;
        } else if (value instanceof Long) {
            Object redacted = params != null && params.getRedactionMappings() != null ? params.getRedactionMappings().get(value) : null;
            return redacted != null ? redacted : params != null && params.getDefaultRedaction() != null ? params.getDefaultRedaction() : 0L;
        } else if (value instanceof Double) {
            Object redacted = params != null && params.getRedactionMappings() != null ? params.getRedactionMappings().get(value) : null;
            return redacted != null ? redacted : params != null && params.getDefaultRedaction() != null ? params.getDefaultRedaction() : 0d;
        } else {
            Object redacted = params != null && params.getRedactionMappings() != null ? params.getRedactionMappings().get(value) : null;
            return redacted != null ? redacted : params != null && params.getDefaultRedaction() != null ? params.getDefaultRedaction() : "";
        }
    }

    @Override
    public String reverse(String scope, String table, Object value) {
        throw new IllegalArgumentException("Not supported");
    }

    @Getter
    @AllArgsConstructor
    public static class Params {

        private Object defaultRedaction;

        private Map<Object, Object> redactionMappings;
    }
}