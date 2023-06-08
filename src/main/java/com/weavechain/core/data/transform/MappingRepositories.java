package com.weavechain.core.data.transform;

import com.weavechain.core.data.ConvertUtils;
import lombok.Getter;

import java.util.List;

public class MappingRepositories {

    public static final MappingRepositories INSTANCE = new MappingRepositories();

    @Getter
    private static MappingPersistor persistor;

    public static void setPersistor(MappingPersistor persistor) {
        MappingRepositories.persistor = persistor;

        List<List<String>> mappings = persistor.readMappings();
        if (mappings != null) {
            for (List<String> it : mappings) {
                String key = it.get(0);
                Long mapping = ConvertUtils.convertToLong(it.get(1));
                if (key == null) {
                    INSTANCE.linkedRandomIdsRepository.restoreMapping(null, mapping, it.get(2));
                } else {
                    INSTANCE.randomIdsRepository.restoreMapping(key, mapping, it.get(2));
                }
            }
        }
    }

    @Getter
    private final MappingRepository<Long> randomIdsRepository = new TableSpecificMappingRepository<>();

    @Getter
    private final MappingRepository<String> hashesRepository = new TableAgnosticMappingRepository<>();

    @Getter
    private final MappingRepository<Long> linkedRandomIdsRepository = new TableAgnosticMappingRepository<>();
}