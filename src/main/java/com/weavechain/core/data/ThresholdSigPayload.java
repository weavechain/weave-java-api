package com.weavechain.core.data;

import com.weavechain.core.encoding.Utils;
import lombok.Getter;

import java.util.Map;

@Getter
public class ThresholdSigPayload {

    private final Map<String, ThresholdSig> thresholdSigs = Utils.newConcurrentHashMap();
}
