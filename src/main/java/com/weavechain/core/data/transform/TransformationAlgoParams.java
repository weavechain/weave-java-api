package com.weavechain.core.data.transform;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class TransformationAlgoParams {

    private Quantization.Params quantizationParams;

    private NoiseAdded.Params noiseParams;

    private Encrypt.Params encryptParams;

    private Redaction.Params redactionParams;

    public TransformationAlgoParams quantizationParams(Quantization.Params value) {
        this.quantizationParams = value;
        return this;
    }

    public TransformationAlgoParams noiseParams(NoiseAdded.Params value) {
        this.noiseParams = value;
        return this;
    }

    public TransformationAlgoParams encryptParams(Encrypt.Params value) {
        this.encryptParams = value;
        return this;
    }

    public TransformationAlgoParams redactionParams(Redaction.Params value) {
        this.redactionParams = value;
        return this;
    }

    public TransformationAlgoParams copy() {
        return new TransformationAlgoParams(
                quantizationParams,
                noiseParams,
                encryptParams,
                redactionParams
        );
    }
}