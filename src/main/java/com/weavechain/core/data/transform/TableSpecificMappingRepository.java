package com.weavechain.core.data.transform;

import com.weavechain.core.encoding.Utils;

import java.util.Map;
import java.util.function.Supplier;

public class TableSpecificMappingRepository<T> implements MappingRepository<T> {

    //TODO: kvrocks
    private final Map<String, Map<String, T>> linkedRandomIdsMap = Utils.newConcurrentHashMap();

    private final Map<String, Map<T, String>> reverseLinkIdsMap = Utils.newConcurrentHashMap();

    private final Object sync = new Object();

    @Override
    public T map(String scope, String table, Object value, Supplier<T> generator) {
        if (value == null) {
            return null;
        } else {
            String key = scope + ":" + table;
            Map<String, T> linkedRandomIds = linkedRandomIdsMap.computeIfAbsent(key, (k) -> Utils.newConcurrentHashMap());
            Map<T, String> reverseLinkIds = reverseLinkIdsMap.computeIfAbsent(key, (k) -> Utils.newConcurrentHashMap());

            String serialization = value.toString();
            return linkedRandomIds.computeIfAbsent(serialization,
                (k) -> {
                    synchronized (sync) {
                        T mapping = generator.get();

                        while (reverseLinkIds.containsKey(mapping)) {
                            mapping = generator.get();
                        }

                        reverseLinkIds.computeIfAbsent(mapping, (l) -> serialization);

                        MappingPersistor persistor = MappingRepositories.getPersistor();
                        if (persistor != null) {
                            persistor.persistMapping(key, mapping.toString(), serialization);
                        }

                        return mapping;
                    }
                }
            );
        }
    }

    @Override
    public String reverse(String scope, String table, T value) {
        String key = scope + ":" + table;
        Map<T, String> reverseLinkIds = reverseLinkIdsMap.computeIfAbsent(key, (k) -> Utils.newConcurrentHashMap());

        return reverseLinkIds.get(value);
    }

    @Override
    public void restoreMapping(String key, T mapping, String value) {
        Map<String, T> linkedRandomIds = linkedRandomIdsMap.computeIfAbsent(key, (k) -> Utils.newConcurrentHashMap());
        Map<T, String> reverseLinkIds = reverseLinkIdsMap.computeIfAbsent(key, (k) -> Utils.newConcurrentHashMap());

        linkedRandomIds.put(value, mapping);
        reverseLinkIds.put(mapping, value);
    }
}