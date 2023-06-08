package com.weavechain.core.data.transform;

import com.weavechain.core.data.ConvertUtils;

public class ConvertDouble implements Transformation {

    public ConvertDouble() {
    }

    @Override
    public Object transform(String scope, String table, Object value) {
        if (value == null) {
            return null;
        } else {
            return ConvertUtils.convertToDouble(value) / 1000;
        }
    }

    @Override
    public String reverse(String scope, String table, Object value) {
        return value.toString();
    }
}