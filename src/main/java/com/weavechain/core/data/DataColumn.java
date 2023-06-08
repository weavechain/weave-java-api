package com.weavechain.core.data;

import com.weavechain.core.data.transform.DataTransform;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.function.Supplier;

@Getter
@AllArgsConstructor
public class DataColumn {

    public static final boolean DEFAULT_IS_INDEXED = false;
    public static final boolean DEFAULT_IS_NULLABLE = true;
    public static final boolean DEFAULT_IS_UNIQUE = false;
    public static final boolean DEFAULT_IS_ENCRYPTED = false;
    public static final boolean DEFAULT_ALLOW_PLAINTEXT = true;

    private final String columnName;

    private final DataType type;

    private final DataTransform readTransform;

    private boolean isIndexed;

    private boolean isNullable;

    private boolean isUnique;

    private boolean isEncrypted; //Supported only by DynamoDB right now

    private boolean allowPlaintext; //used in HE context, true if queries are allowed to retrieve this column as is

    private transient final Supplier<Object> defaultValue;
}