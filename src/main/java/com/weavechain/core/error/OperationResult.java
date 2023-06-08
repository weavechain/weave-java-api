package com.weavechain.core.error;

public interface OperationResult {

    OperationScope getTarget();

    boolean isError();

    String getMessage();

    Object getData();

    String getStringData();

    Object getMetadata();

    String getStringMetadata();

    String getIds();

    String getHashes();

    OperationResult toAuditRecord();

    //TODO: add number of actual acks received for writes (in case of error)
}