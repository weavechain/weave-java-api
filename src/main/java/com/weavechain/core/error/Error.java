package com.weavechain.core.error;

public abstract class Error implements OperationResult {

    public abstract String getMessage();

    @Override
    public boolean isError() {
        return true;
    }

    @Override
    public String getData() {
        return null;
    }

    @Override
    public String getStringData() {
        return null;
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