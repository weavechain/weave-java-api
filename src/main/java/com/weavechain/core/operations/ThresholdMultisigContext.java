package com.weavechain.core.operations;

import cafe.cryptography.curve25519.EdwardsPoint;
import cafe.cryptography.curve25519.Scalar;
import com.weavechain.core.data.ThresholdSigEd25519Param;
import com.weavechain.core.data.ThresholdSigPayload;
import com.weavechain.core.encoding.Utils;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;
import java.util.Set;

@Getter
public class ThresholdMultisigContext {

    private final String pubKey;

    private final ThresholdSigOptions options = new ThresholdSigOptions(300);

    private final Map<String, String> uuidPeerMap = Utils.newConcurrentHashMap();

    private final Map<String, Set<EdwardsPoint>> edwardsPoints = Utils.newConcurrentHashMap();

    private final Map<String, Set<Scalar>> signatureShares = Utils.newConcurrentHashMap();

    @Setter
    private ThresholdSigEd25519Param thresholdSigEd25519Param;

    @Setter
    private ThresholdSigPayload thresholdSigPayload = null;


    public ThresholdMultisigContext(String pubKey) {
        this.pubKey = pubKey;
    }
}
