package com.weavechain.core.error;

import com.weavechain.core.encoding.Utils;
import com.weavechain.core.operations.ApiOperationType;
import com.weavechain.core.operations.OperationType;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.util.Map;

@Getter
@EqualsAndHashCode
@AllArgsConstructor
public class OperationScope {

    OperationType operationType;

    String organization;

    String account;

    String scope;

    String table;

    public static OperationScope from(Object data) {
        if (data instanceof String) {
            return Utils.getGson().fromJson((String)data, OperationScope.class);
        } else if (data instanceof Map){
            Map items = (Map)data;
            String type = (String)items.get("operationType");
            //TODO: nicer, we shouldn't need cast ops anywhere in the code
            //TODO: !!! get rid of this valueOf
            return new OperationScope(
                    ApiOperationType.valueOf(type),
                    (String)items.get("organization"),
                    (String)items.get("account"),
                    (String)items.get("scope"),
                    (String)items.get("table")
            );
        } else {
            return null;
        }
    }
}