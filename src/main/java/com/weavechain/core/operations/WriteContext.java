package com.weavechain.core.operations;

import com.weavechain.core.data.Records;
import com.weavechain.core.error.OperationResult;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

@Getter
public class WriteContext {

    static final Logger logger = LoggerFactory.getLogger(WriteContext.class);

    private final String writerPublicKey;

    private final String writerSignature;

    private final List<Records.IntegrityPair> integritySignatures;

    private final WriteOptions options;

    private final AtomicInteger acks;

    private final AtomicInteger hashAcks;

    private final String feeLimit;

    private String sourceIP;

    private OperationResult mergedResult;

    private final Set<String> integrityAcks = new HashSet<>();

    @Setter
    private ThresholdMultisigContext thresholdMultisigContext;

    public WriteContext(String writerPublicKey, String writerSignature, List<Records.IntegrityPair> signatures, String feeLimit, String sourceIP, WriteOptions options) {
        this.writerPublicKey = writerPublicKey;
        this.writerSignature = writerSignature;
        this.integritySignatures = signatures;
        this.options = options;
        this.feeLimit = feeLimit;
        this.sourceIP = sourceIP;

        this.acks = new AtomicInteger(0);
        this.hashAcks = new AtomicInteger(0);
    }

    public WriteContext(String writerPublicKey, String writerSignature, List<Records.IntegrityPair> signatures, String feeLimit, String sourceIP, ThresholdSigOptions options) {
        this(writerPublicKey, writerSignature, signatures, feeLimit, sourceIP, WriteOptions.DEFAULT);
    }

    public boolean ackWrite(OperationResult result) {
        if (result.isError()) {
            //TODO: merge errors
            mergedResult = result;
        }
        return acks.incrementAndGet() >= options.getMinAcks() && hashAcks.get() >= options.getMinHashAcks();
    }

    public boolean ackHash(OperationResult result) {
        if (result.isError()) {
            //TODO: merge errors
            mergedResult = result;
        }
        return hashAcks.incrementAndGet() >= options.getMinHashAcks() && acks.get() >= options.getMinAcks();
    }
}