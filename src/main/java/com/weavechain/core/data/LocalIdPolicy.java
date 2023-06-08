package com.weavechain.core.data;

import lombok.Getter;

@Getter
public class LocalIdPolicy implements IdPolicy {

    public static IdPolicy INSTANCE = new LocalIdPolicy();

    public boolean alwaysGenerate = false;

    @Override
    public Long getRangeStart() {
        return null;
    }

    @Override
    public Long getRangeEnd() {
        return null;
    }
}