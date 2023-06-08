package com.weavechain.core.data.transform;

import java.util.List;

public interface MappingPersistor {

    void persistMapping(String key, String mapping, String value);

    List<List<String>> readMappings();
}