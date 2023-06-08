package com.weavechain.core.data.transform;

public class Erasure implements Transformation {

    @Override
    public Object transform(String scope, String table, Object value) {
        if (value == null) {
            return null;
        } else if (value instanceof Long) {
            return 0L;
        } else if (value instanceof Double) {
            return 0d;
        } else {
            return "";
        }
    }

    @Override
    public String reverse(String scope, String table, Object value) {
        throw new IllegalArgumentException("Not supported");
    }
}