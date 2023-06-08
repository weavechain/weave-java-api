package com.weavechain.core.batching;

import com.weavechain.core.encoding.Utils;

import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class BatchHelper {

    private final Map<RecordBatchLocation, BatchData> batches = Utils.newConcurrentHashMap();

    private final ScheduledExecutorService delayedExecutor = Executors.newScheduledThreadPool(1); //TODO: review if we can have multiple threads or we need to keep the order

    private final ScheduledExecutorService dispatchExecutor = Executors.newScheduledThreadPool(1);

    public long timeTillReady(BatchData batch, BatchingOptions batchingOptions) {
        if (batchingOptions == null
                || batch.getRecords() >= batchingOptions.getWaitRecords()
                || batch.getSize() >= batchingOptions.getWaitSize()) {
            return 0;
        } else {
            long remaining = batchingOptions.getWaitTimeMs() - (System.currentTimeMillis() - batch.getTime());
            return Math.max(remaining, 0);
        }
    }

    public BatchData getBatch(RecordBatchLocation location, int timeoutMs) {
        BatchData currentBatch = batches.computeIfAbsent(location, (k) -> new BatchData(location, timeoutMs));
        if (currentBatch.getQueuedForDispatch().get()) {
            currentBatch = batches.compute(location, (k, v) -> new BatchData(location, timeoutMs));
        }
        return currentBatch;
    }

    public void checkBatch(BatchData currentBatch, BatchingOptions batchingOptions, Runnable function) {
        long remaining = timeTillReady(currentBatch, batchingOptions);
        if (remaining > 0) {
            if (currentBatch.getScheduled().compareAndSet(false, true)) {
                delayedExecutor.schedule(() -> checkBatch(currentBatch, batchingOptions, function), remaining, TimeUnit.MILLISECONDS);
            }
        } else {
            if (currentBatch.getQueuedForDispatch().compareAndSet(false, true)) {
                dispatchExecutor.submit(function);
            }
        }
    }
}