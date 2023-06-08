package com.weavechain.core.data;

public interface IdPolicy {

    boolean isAlwaysGenerate();

    Long getRangeStart();

    Long getRangeEnd();
}