package com.weavechain.core.data.transform;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encrypt.HashFunction;
import com.weavechain.core.encrypt.HashSHA2;
import org.apache.commons.codec.binary.Base64;

public class Hashing implements Transformation {

    private final HashFunction hashFunction = new HashSHA2();

    private final MappingRepository<String> repository;

    public Hashing(MappingRepository<String> repository) {
        this.repository = repository;
    }

    @Override
    public Object transform(String scope, String table, Object value) {
        if (value == null) {
            return null;
        } else {
            return repository.map(scope, table, value,
                    () -> Base64.encodeBase64String(hashFunction.digest(ConvertUtils.convertToString(value)))
            );
        }
    }

    @Override
    public String reverse(String scope, String table, Object value) {
        if (value == null) {
            return null;
        } else {
            return repository.reverse(scope, table, (String)value);
        }
    }
}