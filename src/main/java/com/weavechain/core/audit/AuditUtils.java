package com.weavechain.core.audit;

public class AuditUtils {

    //TODO: move to config
    public static final boolean LOG_DATA = true;

    private static final int TABLENAME_MAX_LEN = 64; //safe limit (also MySQL limit)

    public static final int MAX_LOGGED_SIZE = 1000;

    public static final int MAX_LOGGED_COUNT = 100;

    public static final String AUDIT_API_KEYS_TABLE = "api_keys";

    public static final String AUDIT_TASKS_TABLE = "tasks";

    public static final String AUDIT_ACCOUNT_PREFIX = "weave_audit_account";

    public static final String AUDIT_TABLE_PREFIX = "weave_audit_table";

    public static String getAuditAccount(String account) {
        return "weave.audit." + account;
    }

    public static String getAuditTableNameForAccount(String account) {
        String name = AUDIT_ACCOUNT_PREFIX + "_" + (account != null ? account : "").replaceAll("[^a-zA-Z0-9_-]", "_").toLowerCase();
        return name.length() > TABLENAME_MAX_LEN ? name.substring(0, TABLENAME_MAX_LEN) : name;
    }

    public static String getAuditTableNameForTable(String scope, String table) {
        String name = AUDIT_TABLE_PREFIX
                + (scope != null && scope.length() > 0 ? "_" : "")
                + (scope != null ? scope : "").replaceAll("[^a-zA-Z0-9_-]", "_").toLowerCase()
                + (table != null && table.length() > 0 ? "_" : "")
                + (table != null ? table : "").replaceAll("[^a-zA-Z0-9_-]", "_").toLowerCase();
        return name.length() > TABLENAME_MAX_LEN ? name.substring(0, TABLENAME_MAX_LEN) : name;
    }

}