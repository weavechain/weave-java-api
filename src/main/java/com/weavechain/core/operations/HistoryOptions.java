package com.weavechain.core.operations;

import lombok.Getter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class HistoryOptions {
    @Getter
    private final Set<String> operationTypes = new HashSet<>();

    public HistoryOptions withOperationTypes(String... operationTypes) {
        this.operationTypes.addAll(Arrays.asList(operationTypes));
        return this;
    }
}
