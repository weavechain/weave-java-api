package com.weavechain.core.data;

import java.util.HashMap;
import java.util.Map;

public class IdPolicies {

    private static final Map<String, IdPolicy> policies = new HashMap<>();

    static {
        policies.put("local", LocalIdPolicy.INSTANCE);
        policies.put("localOverwrite", LocalOverwriteIdPolicy.INSTANCE);
    }

    public static IdPolicy getIdPolicy(String policy) {
        IdPolicy idPolicy = policy != null ? policies.get(policy) : null;
        return idPolicy != null ? idPolicy : LocalIdPolicy.INSTANCE;
    }
}