package com.weavechain.core.data.transform;

import ch.obermuhlner.math.big.BigDecimalMath;
import com.google.common.math.BigIntegerMath;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.security.SecureRandom;

@AllArgsConstructor
public class Quantization implements Transformation {

    static final Logger logger = LoggerFactory.getLogger(Quantization.class);

    private static final RoundingMode ROUNDING_MODE = RoundingMode.HALF_EVEN;

    private static final MathContext MATH_CONTEXT = MathContext.DECIMAL64;

    private static final double LN_2 = Math.log(2);

    private static final SecureRandom RND = new SecureRandom();

    @Override
    public Object transform(String scope, String table, Object value) {
        TransformationAlgoParams algoParams = DataLayout.getTransformAlgoParams(scope, table);
        Params params = algoParams != null ? algoParams.getQuantizationParams() : null;

        if (params == null) {
            logger.warn("Quantization transform with no private params defined, erasing");
            return null;
        }

        if (value == null) {
            return null;
        } else if (value instanceof Integer) {
            if ("sqrt".equals(params.getTransform())) {
                value = (int)Math.sqrt((double)value);
            } else if ("log".equals(params.getTransform())) {
                value = (int)Math.log((double)value);
            } else if ("log2".equals(params.getTransform())) {
                value = (int)(Math.log((double)value) / LN_2);
            } else if ("log10".equals(params.getTransform())) {
                value = (int)Math.log10((double)value);
            }

            if (params.getStep() != null) {
                Integer step = ConvertUtils.convertToInteger(params.getStep());
                value = (((Integer)value) / step) * step;
            }

            if (params.getScaling() != null) {
                value = (int)(((Integer) value) * ConvertUtils.convertToDouble(params.getScaling()));
            }

            if (params.getNoiseRange() != null) {
                value = (Integer) value + RND.nextInt() % ConvertUtils.convertToInteger(params.getNoiseRange());
            }
        } else if (value instanceof Long) {
            if ("sqrt".equals(params.getTransform())) {
                value = (long)Math.sqrt((double)value);
            } else if ("log".equals(params.getTransform())) {
                value = (long)Math.log((double)value);
            } else if ("log2".equals(params.getTransform())) {
                value = (long)(Math.log((double)value) / LN_2);
            } else if ("log10".equals(params.getTransform())) {
                value = (long)Math.log10((double)value);
            }

            if (params.getStep() != null) {
                Long step = ConvertUtils.convertToLong(params.getStep());
                value = (((Long)value) / step) * step;
            }

            if (params.getScaling() != null) {
                value = (long)(((Long) value) * ConvertUtils.convertToDouble(params.getScaling()));
            }

            if (params.getNoiseRange() != null) {
                value = (Long) value + RND.nextLong() % ConvertUtils.convertToLong(params.getNoiseRange());
            }
        } else if (value instanceof Float) {
            if ("sqrt".equals(params.getTransform())) {
                value = (float)Math.sqrt((double)value);
            } else if ("log".equals(params.getTransform())) {
                value = (float)Math.log((double)value);
            } else if ("log2".equals(params.getTransform())) {
                value = (float)(Math.log((double)value) / LN_2);
            } else if ("log10".equals(params.getTransform())) {
                value = (float)Math.log10((double)value);
            }

            if (params.getStep() != null) {
                Float step = ConvertUtils.convertToFloat(params.getStep());
                value = Math.round(((Float)value) / step) * step;
            }

            if (params.getScaling() != null) {
                value = ((Float) value) * ConvertUtils.convertToFloat(params.getScaling());
            }

            if (params.getNoiseRange() != null) {
                value = (Float) value + RND.nextFloat() * ConvertUtils.convertToFloat(params.getNoiseRange());
            }
        } else if (value instanceof Double) {
            if ("sqrt".equals(params.getTransform())) {
                value = Math.sqrt((double)value);
            } else if ("log".equals(params.getTransform())) {
                value = Math.log((double)value);
            } else if ("log2".equals(params.getTransform())) {
                value = (Math.log((double)value) / LN_2);
            } else if ("log10".equals(params.getTransform())) {
                value = Math.log10((double)value);
            }

            if (params.getStep() != null) {
                Double step = ConvertUtils.convertToDouble(params.getStep());
                value = Math.round(((Double)value) / step) * step;
            }

            if (params.getScaling() != null) {
                value = ((Double) value) * ConvertUtils.convertToDouble(params.getScaling());
            }

            if (params.getNoiseRange() != null) {
                value = (Double) value + RND.nextDouble() * ConvertUtils.convertToDouble(params.getNoiseRange());
            }
        } else if (value instanceof BigInteger) {
            if ("sqrt".equals(params.getTransform())) {
                value = ((BigInteger)value).sqrt();
            } else if ("log".equals(params.getTransform())) {
                value = BigInteger.valueOf((long)((BigIntegerMath.log2((BigInteger)value, ROUNDING_MODE) * LN_2)));
            } else if ("log2".equals(params.getTransform())) {
                value = BigInteger.valueOf(BigIntegerMath.log2((BigInteger)value, ROUNDING_MODE));
            } else if ("log10".equals(params.getTransform())) {
                value = BigInteger.valueOf(BigIntegerMath.log10((BigInteger)value, ROUNDING_MODE));
            }

            if (params.getStep() != null) {
                BigInteger step = ConvertUtils.convertToBigInteger(params.getStep());
                value = ((BigInteger)value).divide(step).multiply(step);
            }

            if (params.getScaling() != null) {
                value = new BigDecimal((BigInteger) value).multiply(ConvertUtils.convertToBigDecimal(params.getScaling())).toBigInteger();
            }

            if (params.getNoiseRange() != null) {
                value = ((BigInteger) value).add(BigInteger.valueOf(RND.nextLong() % ConvertUtils.convertToLong(params.getNoiseRange())));
            }
        } else if (value instanceof BigDecimal) {
            if ("sqrt".equals(params.getTransform())) {
                value = ((BigDecimal)value).sqrt(MATH_CONTEXT);
            } else if ("log".equals(params.getTransform())) {
                value = BigDecimalMath.log2((BigDecimal)value, MATH_CONTEXT).multiply(BigDecimal.valueOf(LN_2));
            } else if ("log2".equals(params.getTransform())) {
                value = BigDecimalMath.log2((BigDecimal)value, MATH_CONTEXT);
            } else if ("log10".equals(params.getTransform())) {
                value = BigDecimalMath.log10((BigDecimal)value, MATH_CONTEXT);
            }

            if (params.getStep() != null) {
                BigDecimal step = ConvertUtils.convertToBigDecimal(params.getStep());
                value = ((BigDecimal)value).divide(step, MATH_CONTEXT).round(MATH_CONTEXT).multiply(step);
            }

            if (params.getScaling() != null) {
                value = ((BigDecimal) value).multiply(ConvertUtils.convertToBigDecimal(params.getScaling()));
            }

            if (params.getNoiseRange() != null) {
                value = ((BigDecimal) value).add(BigDecimal.valueOf(RND.nextDouble() * ConvertUtils.convertToDouble(params.getNoiseRange())));
            }
        } else {
            logger.warn("Quantization transform for unknown type " + value.getClass().getName() + ", erasing");
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

        private final String transform; //Supported: sqrt, log, log2, log10

        private final Object step;

        private final Object scaling;

        private final Object noiseRange;
    }
}