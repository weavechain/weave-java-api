package com.weavechain.core.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.concurrent.CountDownLatch;

@Getter
@AllArgsConstructor
public class ThresholdSig {

    @Setter
    private byte[] publicKey;

    private String table;

    private Long batchStartId;

    private Long batchEndId;

    private final StringBuffer metadataBuffer = new StringBuffer();

    private String message;

    private transient CountDownLatch edwardsPointLatch;

    private transient CountDownLatch signatureShareLatch;

    @Setter
    private byte[] edwardsPoint;

    @Setter
    private byte[] edwardsPointScalar;

    @Setter
    private byte[] signatureShare;

    @Setter
    private byte[] signature;

    /** in delete flows we need to know the identifier on chain of the batch, so we know which batch to update on chain */
    @Setter
    private Long previousOnChainId;

    public ThresholdSig(String table, Long batchStartId, Long batchEndId, String message, int t) {
        this.table = table;
        this.batchStartId = batchStartId;
        this.batchEndId = batchEndId;
        this.message = message;
        this.edwardsPointLatch = new CountDownLatch(t);
        this.signatureShareLatch = new CountDownLatch(t);
    }
}
