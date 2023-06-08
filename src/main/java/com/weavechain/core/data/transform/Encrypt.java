package com.weavechain.core.data.transform;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.encrypt.EncryptionConfig;
import com.weavechain.core.encrypt.FieldEncrypt;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.IdentityHashMap;

@AllArgsConstructor
public class Encrypt implements Transformation {

    static final Logger logger = LoggerFactory.getLogger(Encrypt.class);

    private static final IdentityHashMap<Params, FieldEncrypt> cache = new IdentityHashMap<>();

    @Override
    public Object transform(String scope, String table, Object value) {
        TransformationAlgoParams algoParams = DataLayout.getTransformAlgoParams(scope, table);
        Params params = algoParams != null ? algoParams.getEncryptParams() : null;

        if (params == null) {
            logger.warn("Encrypt transform with no private params defined, erasing");
            return null;
        }

        FieldEncrypt enc = getFieldEncrypt(params);
        return ConvertUtils.convertToString(enc.encrypt(value));
    }

    @Override
    public String reverse(String scope, String table, Object value) {
        TransformationAlgoParams algoParams = DataLayout.getTransformAlgoParams(scope, table);
        Params params = algoParams != null ? algoParams.getEncryptParams() : null;

        if (params == null) {
            logger.warn("Encrypt transform with no private params defined, erasing");
            return null;
        }

        FieldEncrypt enc = getFieldEncrypt(params);
        return ConvertUtils.convertToString(enc.decrypt(value));
    }

    private static FieldEncrypt getFieldEncrypt(Params params) {
        FieldEncrypt enc;
        synchronized (cache) {
            enc = cache.get(params);
            if (enc == null) {
                enc = FieldEncrypt.getEncryptor(params.getConfig().getType());
                enc.init(params.getConfig().getSecretKey(), params.getConfig().getSalt());
                cache.put(params, enc);
            }
        }
        return enc;
    }

    @Getter
    @AllArgsConstructor
    public static class Params {

        private final EncryptionConfig config;
    }
}