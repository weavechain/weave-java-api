package com.weavechain.core.data.transform;

import java.util.concurrent.ThreadLocalRandom;

public class RandomId implements Transformation {

    private final MappingRepository<Long> repository;

    public RandomId(MappingRepository<Long> repository) {
        this.repository = repository;
    }

    @Override
    public Object transform(String scope, String table, Object value) {
        if (value == null) {
            return null;
        } else {
            return repository.map(scope, table, value, RandomId::generateRandomId);
        }
    }

    private static long generateRandomId() {
        return Math.abs(ThreadLocalRandom.current().nextLong());
    }

    @Override
    public String reverse(String scope, String table, Object value) {
        if (value == null) {
            return null;
        } else {
            return repository.reverse(scope, table, (Long)value);
        }
    }
}