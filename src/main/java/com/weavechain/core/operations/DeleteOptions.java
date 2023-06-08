package com.weavechain.core.operations;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@ToString
public class DeleteOptions {
    @Setter
    private boolean allowDistribute;

    private String correlationUuid;

    @Setter
    private ThresholdMultisigContext context;

    public static final DeleteOptions DELETE_DEFAULT = new DeleteOptions(true, null, null);

    public DeleteOptions copy() {
        return new DeleteOptions(allowDistribute, correlationUuid, context);
    }
}
