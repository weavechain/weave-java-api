package com.weavechain.core.data.filter;

import com.weavechain.core.data.DataLayout;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Getter
@AllArgsConstructor
public class Filter {

    //Simple filter that can be applied to [almost] all databases before the query and evaluated on external events dispatch
    //TODO: more flexible post-filtering

    public static final Filter NONE = new Filter(null, null, null, null, null, null);

    public static final String RANDOM_MARKER = "__RANDOM__";

    private final FilterOp op;

    private final Map<String, Direction> order; //does not work for certain DBs when subscribing and streaming. To use a linkedmap to preserve priorities

    private Integer limit; //does not work for certain DBs when subscribing and streaming

    private final List<String> collapsing;

    private final List<String> columns;

    private final FilterOp postFilterOp;

    @Override
    public boolean equals(Object other) {
        if (other instanceof Filter) {
            Filter o = (Filter)other;
            return Objects.equals(op, o.op)
                && Objects.equals(order, o.order)
                && Objects.equals(limit, o.limit)
                && Objects.equals(collapsing, o.collapsing)
                && Objects.equals(columns, o.columns)
                && Objects.equals(postFilterOp, o.postFilterOp);
        } else {
            return false;
        }
    }

    public boolean matches(List<Object> record, DataLayout layout) {
        return op == null || op.matches(record, layout);
    }

    public boolean matches(Map<String, Object> record, DataLayout layout) {
        return op == null || op.matches(record, layout);
    }

    @SuppressWarnings("unchecked")
    public void postFilter(List<Map<String, Object>> result) {
        //used for DBs that don't apply the filtering before query
        if (result != null) {
            if (order != null && order.size() > 0) {
                result.sort((o1, o2) -> {
                    for (Map.Entry<String, Direction> it : order.entrySet()) {
                        Comparable v1 = (Comparable)o1.get(it.getKey());
                        Comparable v2 = (Comparable)o2.get(it.getKey());
                        if (v1 == null && v2 != null) {
                            return Direction.ASC.equals(it.getValue()) ? -1 : 1;
                        } else if (v1 != null && v2 == null) {
                            return Direction.ASC.equals(it.getValue()) ? 1 : -1;
                        } else {
                            int res = Direction.ASC.equals(it.getValue())
                                    ? (v1 == null && v2 == null ? 0 : (v1 == null ? -1 : v1.compareTo(v2)))
                                    : (v1 == null && v2 == null ? 0 : (v1 == null ? 1 : v2.compareTo(v1)));
                            if (res != 0) {
                                return res;
                            }
                        }
                    }
                    return 0;
                });

                if (limit != null && limit > 0) {
                    List<Map<String, Object>> filtered = new ArrayList<>(result.subList(0, Math.min(limit, result.size())));
                    result.clear();
                    result.addAll(filtered);
                }
            }
        }
    }
}