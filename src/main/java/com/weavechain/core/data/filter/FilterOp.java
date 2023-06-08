package com.weavechain.core.data.filter;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.DataType;
import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@Getter
@AllArgsConstructor
public class FilterOp {

    static final Logger logger = LoggerFactory.getLogger(FilterOp.class);

    private final Operation operation;

    private final FilterOp left;

    private final FilterOp right;

    private final Object value;

    /**
     * During debug it helps sometimes to see what the filter is doing
     */
    @Override
    public String toString() {
        return "("
                + (left != null ? left.toString() + " " : "")
                + operation.toString() + " "
                + (right != null ? right.toString() : value.toString())
                + ")";
    }

    public static FilterOp field(String field) {
        return new FilterOp(Operation.field, null, null, field);
    }

    public static FilterOp value(Object value) {
        return new FilterOp(Operation.value, null, null, value);
    }

    public static FilterOp eq(String field, Object value) {
        return new FilterOp(Operation.eq, field(field), value(value), null);
    }

    public static FilterOp neq(String field, Object value) {
        return new FilterOp(Operation.neq, field(field), value(value), null);
    }

    public static FilterOp in(String field, List<Object> values) {
        return new FilterOp(Operation.in, field(field), value(values), null);
    }

    public static FilterOp notin(String field, List<Object> values) {
        return new FilterOp(Operation.notin, field(field), value(values), null);
    }

    public static FilterOp gt(String field, Object value) {
        return new FilterOp(Operation.gt, field(field), value(value), null);
    }

    public static FilterOp gte(String field, Object value) {
        return new FilterOp(Operation.gte, field(field), value(value), null);
    }

    public static FilterOp lt(String field, Object value) {
        return new FilterOp(Operation.lt, field(field), value(value), null);
    }

    public static FilterOp lte(String field, Object value) {
        return new FilterOp(Operation.lte, field(field), value(value), null);
    }

    public static FilterOp and(FilterOp expr1, FilterOp expr2) {
        return new FilterOp(Operation.and, expr1, expr2, null);
    }

    public static FilterOp and(FilterOp expr1, FilterOp expr2, FilterOp... expressions) {
        FilterOp res = new FilterOp(Operation.and, expr1, expr2, null);
        for (FilterOp expr : expressions) {
            res = new FilterOp(Operation.and, res, expr, null);
        }
        return res;
    }

    public static FilterOp or(FilterOp expr1, FilterOp expr2) {
        return new FilterOp(Operation.or, expr1, expr2, null);
    }

    public static FilterOp or(FilterOp expr1, FilterOp expr2, FilterOp... expressions) {
        FilterOp res = new FilterOp(Operation.or, expr1, expr2, null);
        for (FilterOp expr : expressions) {
            res = new FilterOp(Operation.or, res, expr, null);
        }
        return res;
    }

    public static FilterOp not(FilterOp expr) {
        return new FilterOp(Operation.not, expr, null, null);
    }

    public boolean matches(List<Object> record, DataLayout layout) {
        if (Operation.not.equals(operation)) {
            return !left.matches(record, layout);
        } if (Operation.and.equals(operation)) {
            return left.matches(record, layout) && right.matches(record, layout);
        } if (Operation.or.equals(operation)) {
            return left.matches(record, layout) || right.matches(record, layout);
        } if (Operation.eq.equals(operation)) {
            return isEqual(record, layout);
        } if (Operation.neq.equals(operation)) {
            return !isEqual(record, layout);
        } if (Operation.in.equals(operation)) {
            return isIn(record, layout);
        } if (Operation.notin.equals(operation)) {
            return !isIn(record, layout);
        } if (Operation.gt.equals(operation)) {
            return compare(record, layout) > 0;
        } if (Operation.gte.equals(operation)) {
            return compare(record, layout) >= 0;
        } if (Operation.lt.equals(operation)) {
            return compare(record, layout) < 0;
        } if (Operation.lte.equals(operation)) {
            return compare(record, layout) <= 0;
        } if (Operation.contains.equals(operation)) {
            return contains(record, layout);
        } else {
            throw new IllegalArgumentException("Unknown operation");
        }
    }

    public boolean matches(Map<String, Object> record, DataLayout layout) {
        if (Operation.not.equals(operation)) {
            return !left.matches(record, layout);
        } if (Operation.and.equals(operation)) {
            return left.matches(record, layout) && right.matches(record, layout);
        } if (Operation.or.equals(operation)) {
            return left.matches(record, layout) || right.matches(record, layout);
        } if (Operation.eq.equals(operation)) {
            return isEqual(record, layout);
        } if (Operation.neq.equals(operation)) {
            return !isEqual(record, layout);
        } if (Operation.in.equals(operation)) {
            return isIn(record, layout);
        } if (Operation.notin.equals(operation)) {
            return !isIn(record, layout);
        } if (Operation.gt.equals(operation)) {
            return compare(record, layout) > 0;
        } if (Operation.gte.equals(operation)) {
            return compare(record, layout) >= 0;
        } if (Operation.lt.equals(operation)) {
            return compare(record, layout) < 0;
        } if (Operation.lte.equals(operation)) {
            return compare(record, layout) <= 0;
        } else {
            throw new IllegalArgumentException("Unknown operation");
        }
    }

    private boolean isEqual(List<Object> record, DataLayout layout) {
        String field = (String)left.getValue();
        FieldValue fieldVal = fieldValue(record, field, layout);
        Object other = ConvertUtils.convert(right.getValue(), fieldVal.getType());
        return Objects.equals(fieldVal.getValue(), other);
    }


    private boolean isIn(List<Object> record, DataLayout layout) {
        String field = (String)left.getValue();
        if (right.getValue() instanceof List) {
            return isIn(record, layout, field, (List)right.getValue());
        } else {
            return isEqual(record, layout);
        }
    }

    private boolean isIn(List<Object> record, DataLayout layout, String field, List<Object> values) {
        FieldValue fieldVal = fieldValue(record, field, layout);
        Object converted = ConvertUtils.convert(fieldVal.getValue(), fieldVal.getType());

        for (Object value : values) {
            Object other = ConvertUtils.convert(value, fieldVal.getType());
            if (Objects.equals(converted, other)) {
                return true;
            }
        }
        return false;
    }

    private boolean isIn(Map<String, Object> record, DataLayout layout, String field, List<Object> values) {
        FieldValue fieldVal = fieldValue(record, field, layout);
        Object converted = ConvertUtils.convert(fieldVal.getValue(), fieldVal.getType());

        for (Object value : values) {
            Object other = ConvertUtils.convert(value, fieldVal.getType());
            if (Objects.equals(converted, other)) {
                return true;
            }
        }
        return false;
    }

    private int compare(List<Object> record, DataLayout layout) {
        String field = (String)left.getValue();
        FieldValue fieldVal = fieldValue(record, field, layout);
        Object other = ConvertUtils.convert(right.getValue(), fieldVal.getType());
        return fieldVal.getValue().compareTo(other);
    }

    private boolean contains(List<Object> record, DataLayout layout) {
        String field = (String)left.getValue();
        FieldValue fieldVal = fieldValue(record, field, layout);
        Object other = ConvertUtils.convert(right.getValue(), fieldVal.getType());
        return fieldVal.getValue().toString().contains(other.toString());
    }

    private boolean isEqual(Map<String, Object> record, DataLayout layout) {
        String field = (String)left.getValue();
        FieldValue fieldVal = fieldValue(record, field, layout);
        Object other = ConvertUtils.convert(right.getValue(), fieldVal.getType());
        return Objects.equals(fieldVal.getValue(), other);
    }

    private boolean isIn(Map<String, Object> record, DataLayout layout) {
        String field = (String)left.getValue();
        Object values = record.get(field);
        if (values instanceof List) {
            return isIn(record, layout, field, (List) values);
        } else {
            return isEqual(record, layout);
        }
    }

    private int compare(Map<String, Object> record, DataLayout layout) {
        String field = (String)left.getValue();
        FieldValue fieldVal = fieldValue(record, field, layout);
        Comparable other = ConvertUtils.convert(right.getValue(), fieldVal.getType());
        return fieldVal.getValue().compareTo(other);
    }

    private FieldValue fieldValue(Map<String, Object> record, String field, DataLayout layout) {
        if (field.startsWith("json:")) {
            return jsonFieldValue(record, field, layout);
        } else {
            DataType type = layout.getType(field);
            if (type == null) {
                throw new IllegalArgumentException("Unknown field " + field);
            } else {
                Object value = record.get(field);
                return new FieldValue(
                        type,
                        ConvertUtils.convert(value, type)
                );
            }
        }
    }

    private static FieldValue jsonFieldValue(Map<String, Object> record, String field, DataLayout layout) {
        String[] path = field.split(":");
        if (path.length == 3) {
            try {
                String tableField = path[1];
                String jsonField = path[2];

                DataType type = layout.getType(tableField);
                String json = ConvertUtils.convertToString(record.get(tableField));
                if (json != null) {
                    Map<String, Object> items = Utils.getGson().fromJson(json, Map.class);
                    Comparable result = (Comparable)items.get(jsonField);
                    return new FieldValue(
                            ConvertUtils.genericTypeOf(result),
                            result
                    );
                } else {
                    return null;
                }
            } catch (Exception e) {
                logger.error("Failed JSON parsing", e);
                return null;
            }
        } else {
            throw new IllegalArgumentException("Unknown field " + field);
        }
    }

    private FieldValue fieldValue(List<Object> record, String field, DataLayout layout) {
        if (field.startsWith("json:")) {
            return jsonFieldValue(record, field, layout);
        } else {
            DataType type = layout.getType(field);
            if (type == null) {
                throw new IllegalArgumentException("Unknown field " + field);
            } else {
                Object value = record.get(layout.getIndex(field));
                return new FieldValue(
                        type,
                        ConvertUtils.convert(value, type)
                );
            }
        }
    }


    private static FieldValue jsonFieldValue(List<Object> record, String field, DataLayout layout) {
        String[] path = field.split(":");
        if (path.length == 3) {
            try {
                String tableField = path[1];
                String jsonField = path[2];

                DataType type = layout.getType(tableField);
                String json = ConvertUtils.convertToString(record.get(layout.getIndex(tableField)));
                if (json != null) {
                    Map<String, Object> items = Utils.getGson().fromJson(json, Map.class);
                    Comparable result = (Comparable)items.get(jsonField);
                    return new FieldValue(
                            ConvertUtils.genericTypeOf(result),
                            result
                    );
                } else {
                    return null;
                }
            } catch (Exception e) {
                logger.error("Failed JSON parsing", e);
                return null;
            }
        } else {
            throw new IllegalArgumentException("Unknown field " + field);
        }
    }

    @Getter
    @AllArgsConstructor
    static class FieldValue {

        private final DataType type;

        private final Comparable value;
    }
}