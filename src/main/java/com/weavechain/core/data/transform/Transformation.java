package com.weavechain.core.data.transform;

public interface Transformation {

    Object transform(String scope, String table, Object value);

    String reverse(String scope, String table, Object value);
}