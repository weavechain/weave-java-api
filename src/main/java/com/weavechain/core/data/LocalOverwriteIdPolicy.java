package com.weavechain.core.data;

import lombok.Getter;

@Getter
public class LocalOverwriteIdPolicy implements IdPolicy {

    public static IdPolicy INSTANCE = new LocalOverwriteIdPolicy();

    public boolean alwaysGenerate = true;

    @Override
    public Long getRangeStart() {
        return null;
    }

    @Override
    public Long getRangeEnd() {
        return null;
    }
}