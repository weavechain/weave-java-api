package com.weavechain.core.permissions;

import lombok.Getter;

import java.util.Locale;

public class PermissionType {

    public static final String[] PERMISSIONS = new String[] {
            "create",
            "drop",
            "read",
            "write",
            "view",
            "compute",
            "publish",
            "blacklist",
            "count"
    };

    public static final PermissionType NONE = new PermissionType(0);

    public static final PermissionType CREATE = new PermissionType(1);

    public static final PermissionType DROP = new PermissionType(2);

    public static final PermissionType READ = new PermissionType(4);

    public static final PermissionType WRITE = new PermissionType(8);

    public static final PermissionType VIEW = new PermissionType(16);

    public static final PermissionType COMPUTE = new PermissionType(32);

    public static final PermissionType PUBLISH = new PermissionType(64);

    public static final PermissionType DELETE = new PermissionType(128);

    public static final PermissionType BLACKLIST = new PermissionType(256);

    public static final PermissionType COUNT = new PermissionType(512);

    public static final PermissionType ALL = new PermissionType(
            CREATE.value |
                    DROP.value |
                    READ.value |
                    WRITE.value |
                    VIEW.value |
                    COMPUTE.value |
                    PUBLISH.value |
                    DELETE.value |
                    COUNT.value
    );

    @Getter
    private final int value;

    public PermissionType(int value) {
        this.value = value;
    }

    public PermissionType grant(PermissionType perm) {
        return new PermissionType(value | perm.getValue());
    }

    public PermissionType revoke(PermissionType perm) {
        return new PermissionType(value & ~perm.getValue());
    }

    public static PermissionType of(String name) {
        if ("none".equals(name.toLowerCase(Locale.ROOT))) {
            return NONE;
        } else if ("create".equals(name.toLowerCase(Locale.ROOT))) {
            return CREATE;
        } else if ("drop".equals(name.toLowerCase(Locale.ROOT))) {
            return DROP;
        } else if ("view".equals(name.toLowerCase(Locale.ROOT))) {
            return VIEW;
        } else if ("read".equals(name.toLowerCase(Locale.ROOT))) {
            return READ;
        } else if ("write".equals(name.toLowerCase(Locale.ROOT))) {
            return WRITE;
        } else if ("compute".equals(name.toLowerCase(Locale.ROOT))) {
            return COMPUTE;
        } else if ("publish".equals(name.toLowerCase(Locale.ROOT))) {
            return PUBLISH;
        } else if ("delete".equals(name.toLowerCase(Locale.ROOT))) {
            return DELETE;
        } else if ("blacklist".equals(name.toLowerCase(Locale.ROOT))) {
            return BLACKLIST;
        } else if ("all".equals(name.toLowerCase(Locale.ROOT))) {
            return ALL;
        } else {
            return NONE;
        }
    }
}
