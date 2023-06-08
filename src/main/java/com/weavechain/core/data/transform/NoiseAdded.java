package com.weavechain.core.data.transform;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;

@AllArgsConstructor
public class NoiseAdded implements Transformation {

    static final Logger logger = LoggerFactory.getLogger(NoiseAdded.class);

    private static final SecureRandom RND = new SecureRandom();

    @Override
    public Object transform(String scope, String table, Object value) {
        TransformationAlgoParams algoParams = DataLayout.getTransformAlgoParams(scope, table);
        Params params = algoParams != null ? algoParams.getNoiseParams() : null;

        if (params == null || params.getRange() == null) {
            logger.warn("Noise transform with no private params defined, erasing");
            return null;
        }

        if (value == null) {
            return null;
        } else if (value instanceof Integer) {
            value = (Integer)value + RND.nextInt() % ConvertUtils.convertToInteger(params.getRange());
        } else if (value instanceof Long) {
            value = (Long)value + RND.nextLong() % ConvertUtils.convertToLong(params.getRange());
        } else if (value instanceof Float) {
            value = (Float)value + RND.nextFloat() * ConvertUtils.convertToFloat(params.getRange());
        } else if (value instanceof Double) {
            value = (Double)value + RND.nextDouble() * ConvertUtils.convertToDouble(params.getRange());
        } else if (value instanceof BigInteger) {
            value = ((BigInteger)value).add(BigInteger.valueOf(RND.nextLong() % ConvertUtils.convertToLong(params.getRange())));
        } else if (value instanceof BigDecimal) {
            value = ((BigDecimal)value).add(BigDecimal.valueOf(RND.nextDouble() * ConvertUtils.convertToDouble(params.getRange())));
        } else {
            logger.warn("Noise transform for unknown type " + value.getClass().getName() + ", erasing");
            value = null;
        }
        return value;
    }

    @Override
    public String reverse(String scope, String table, Object value) {
        throw new IllegalArgumentException("Not supported");
    }

    @Getter
    @AllArgsConstructor
    public static class Params {

        private final Object range;
    }
}