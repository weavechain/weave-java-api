package com.weavechain.core.data.transform;

import com.weavechain.core.data.ConvertUtils;

public class ConvertLong implements Transformation {

    public ConvertLong() {
    }

    @Override
    public Object transform(String scope, String table, Object value) {
        if (value == null) {
            return null;
        } else {
            return ConvertUtils.convertToLong(value);
        }
    }

    @Override
    public String reverse(String scope, String table, Object value) {
        return value.toString();
    }
}