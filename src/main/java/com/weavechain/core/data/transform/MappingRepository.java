package com.weavechain.core.data.transform;

import java.util.function.Supplier;

public interface MappingRepository<T> {

    T map(String scope, String table, Object value, Supplier<T> generator);

    String reverse(String scope, String table, T value);

    void restoreMapping(String key, T mapping, String value);
}