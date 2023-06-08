package com.weavechain.core.permissions;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class Permission {

    public static final List<String> ALL = null;

    private final PermissionType type;

    private final String scope;

    private final List<String> tables;

    public static Permission of(PermissionType type, String scope, List<String> tables) {
        return new Permission(type, scope, tables);
    }
}
