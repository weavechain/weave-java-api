package com.weavechain.core.data.transform;

import com.weavechain.core.encoding.Utils;

import java.util.Map;
import java.util.function.Supplier;

public class TableAgnosticMappingRepository<T> implements MappingRepository<T> {

    //TODO: kvrocks
    private final Map<String, T> linkedRandomIds = Utils.newConcurrentHashMap();

    private final Map<T, String> reverseLinkIds = Utils.newConcurrentHashMap();

    private final Object sync = new Object();

    @Override
    public T map(String scope, String table, Object value, Supplier<T> generator) {
        if (value == null) {
            return null;
        } else {
            String serialization = value.toString();

            return linkedRandomIds.computeIfAbsent(serialization,
                (k) -> {
                    synchronized (sync) {
                        T id = generator.get();
                        while (reverseLinkIds.containsKey(id)) {
                            id = generator.get();
                        }
                        reverseLinkIds.computeIfAbsent(id, (l) -> serialization);

                        MappingPersistor persistor = MappingRepositories.getPersistor();
                        if (persistor != null) {
                            persistor.persistMapping(null, id.toString(), serialization);
                        }

                        return id;
                    }
                }
            );
        }
    }

    @Override
    public String reverse(String scope, String table, T value) {
        return reverseLinkIds.get(value);
    }

    @Override
    public void restoreMapping(String key, T mapping, String value) {
        linkedRandomIds.put(value, mapping);
        reverseLinkIds.put(mapping, value);
    }
}