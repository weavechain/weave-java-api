package com.weavechain.core.batching;

import com.weavechain.core.data.Records;
import com.weavechain.core.error.OperationResult;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;
import com.weavechain.core.utils.CompletableFuture;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Getter
public class BatchData {

    private final RecordBatchLocation location;

    private final List<Records> items = new ArrayList<>();

    private int records = 0;

    private long size = 0;

    private final long time = System.currentTimeMillis();

    private final AtomicBoolean scheduled = new AtomicBoolean(false);

    private final AtomicBoolean dispatched = new AtomicBoolean(false);

    private final AtomicBoolean queuedForDispatch = new AtomicBoolean(false);

    private final CompletableFuture<OperationResult> result = new CompletableFuture<>();

    public BatchData(RecordBatchLocation location, int timeoutMs) {
        this.location = location;
        result.orTimeout(timeoutMs, TimeUnit.MILLISECONDS);
    }

    public void addRecord(Records records) {
        synchronized (items) {
            items.add(records);

            this.records += records.getItems().size();

            //Local batching by size does not work ok unless we compute the actual serialization size, but that's too time consuming to do.
            // To ignore for now. TODO: find an efficient way to approximate the size
            this.size += records.getSerialization() != null ? records.getSerialization().length() : 0 /*TODO*/;
        }
    }

    public List<Records> getItems() {
        synchronized (items) {
            return new ArrayList<>(items);
        }
    }

    public void addItemsTo(Records records) {
        synchronized (items) {
            for (Records r :items) {
                records.getItems().addAll(r.getItems());
                if (r.getIntegrity() != null) {
                    records.getIntegrity().addAll(r.getIntegrity());
                }
            }
        }
    }
}