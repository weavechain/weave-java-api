package com.weavechain.core.error;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class QuerySuccess implements OperationResult {

    OperationScope target;

    @Getter
    Object data;

    @Override
    public String getStringData() {
        return data != null ? data.toString() : null;
    }

    @Override
    public boolean isError() {
        return false;
    }

    @Override
    public String getMessage() {
        return "OK";
    }


    @Override
    public Object getMetadata() {
        return null;
    }

    @Override
    public String getStringMetadata() {
        return null;
    }

    @Override
    public String getIds() {
        return null;
    }

    @Override
    public String getHashes() {
        return null;
    }

    @Override
    public OperationResult toAuditRecord() {
        return this;
    }
}