package com.weavechain.core.batching;

import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class BatchingOptions {

    public int waitRecords = 0;

    public int waitSize = 0;

    public int waitTimeMs = 0;

    public static BatchingOptions fromJson(Object json, BatchingOptions defaultValue) {
        if (json != null) {
            return Utils.getGson().fromJson(json.toString(), BatchingOptions.class);
        } else {
            return defaultValue;
        }
    }

    public String toJson() {
        return Utils.getGson().toJson(this);
    }

    public static boolean isTriggered(int records, long size, BatchingOptions options) {
        //TODO: drop and unify with check from BatchHelper
        return options == null || records >= options.getWaitRecords() || size >= options.getWaitSize();
    }

    public BatchingOptions waitRecords(int value) {
        this.waitRecords = value;
        return this;
    }

    public BatchingOptions waitSize(int value) {
        this.waitSize = value;
        return this;
    }

    public BatchingOptions waitTimeMs(int value) {
        this.waitTimeMs = value;
        return this;
    }

    public BatchingOptions copy() {
        return new BatchingOptions(
                waitRecords,
                waitSize,
                waitTimeMs
        );
    }

    public static BatchingOptions DEFAULT_NO_BATCHING = new BatchingOptions(
            0,
            0,
            0
    );

    public static BatchingOptions DEFAULT_BATCHING = new BatchingOptions(
            10000,
            1048576,
            250
    );

    public static int INITIAL_HASHING_BATCHES = 10_000;
}