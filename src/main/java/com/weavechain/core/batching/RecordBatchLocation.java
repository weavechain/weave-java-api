package com.weavechain.core.batching;

import com.weavechain.core.operations.WriteOptions;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Getter
@EqualsAndHashCode
@AllArgsConstructor
public class RecordBatchLocation {

    private final String account;

    private final String organization;

    private final String scope;

    private final String table;

    private final WriteOptions writeOptions;
}