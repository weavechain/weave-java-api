package com.weavechain.core.data;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.OutputStream;

@Getter
@AllArgsConstructor
public class OutputContext {

    private static final int DEFAULT_BATCH_SIZE = 16384;

    private final boolean readUnprocessed;

    private final boolean immediate;

    //TODO: when doing streaming for regular DBs, make sure the data is filtered by localUsageOnly and ownDataOnly
    private final OutputStream outputStream;

    private final boolean localUsageOnly;

    private final boolean ownDataOnly;

    private final int batchSize;

    public static final OutputContext DEFAULT = new OutputContext(false, false, null, false, false);

    public static final OutputContext LOCAL_USE = new OutputContext(true, false, null, true, false);

    public static final OutputContext IMMEDIATE = new OutputContext(false, true, null, false, false);

    public static final OutputContext IMMEDIATE_LOCAL_USE = new OutputContext(true, true, null, true, false);

    public OutputContext(boolean readUnprocessed, boolean immediate, OutputStream outputStream, boolean localUsageOnly, boolean ownDataOnly) {
        this(readUnprocessed, immediate, outputStream, localUsageOnly, ownDataOnly, DEFAULT_BATCH_SIZE);
    }
}