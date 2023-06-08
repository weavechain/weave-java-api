package com.weavechain.core.operations;

import com.weavechain.core.permissions.PermissionType;
import lombok.Getter;

import java.util.Locale;

public enum ApiOperationType implements OperationType {

    //TODO: drop the need for this enum

    GENERIC_REQUEST(0),

    CREATE_TABLE(PermissionType.CREATE.getValue()),

    DROP_TABLE(PermissionType.DROP.getValue()),

    READ(PermissionType.READ.getValue()),

    WRITE(PermissionType.WRITE.getValue()),

    VIEW(PermissionType.VIEW.getValue()),

    COMPUTE(PermissionType.COMPUTE.getValue()),

    PUBLISH(PermissionType.PUBLISH.getValue()), //64

    DELETE(PermissionType.DELETE.getValue()), //128

    BLACKLIST(PermissionType.BLACKLIST.getValue()), //256

    COUNT(PermissionType.COUNT.getValue()), //512

    UPLOAD(5089),

    UPLOAD_API(5090),

    FORWARD_API(5091),

    ENABLE_PRODUCT(5092),

    RUN_TASK(5093),

    DOWNLOAD(5094),

    TABLES(5095),

    STORAGE_SIZE(5096),

    LAST(5098),

    READ_TABLE_LAYOUT(5099),

    SUBSCRIBE(5100),

    UNSUBSCRIBE(5101),

    TASK_LINEAGE(5103),

    VERIFY_TASK_LINEAGE(5104),

    TASK_OUTPUT_DATA(5105),

    HE_GET_INPUTS(5106),

    HE_GET_OUTPUTS(5107),

    HE_ENCODE(5108),

    MPC(5109),

    MPC_INIT(5110),

    MPC_PROTO(5111),

    STORAGE_PROOF(5112),

    ZK_STORAGE_PROOF(5113),

    MERKLE_TREE(5114),

    ROOT_HASH(5115),

    MERKLE_PROOF(5116),

    ZK_MERKLE_TREE(5117),

    VERIFY_MERKLE_HASH(5118),

    ZK_PROOF(5119),

    ZK_DATA_PROOF(5120),

    VERIFY_ZK_PROOF(5121),

    MIMC_HASH(5122),

    F_LEARN(5123),

    HISTORY(5124),

    HASH_CHECKPOINT(5125),

    WRITERS(5126),

    TASKS(5127),

    LINEAGE(5128),

    UPDATE_PROOFS(5129),

    PROOFS_LAST_HASH(5130),

    DEPLOY_ORACLE(5203),

    DEPLOY_FEED(5204),

    REMOVE_FEED(5205),

    START_FEED(5206),

    STOP_FEED(5207),

    POST_MESSAGE(5210),

    POLL_MESSAGES(5211),

    PROXY_ENCRYPT(5212),

    PROXY_REENCRYPT(5213),

    BLIND_SIGNATURE(5214),

    ENCRYPTED_REQUEST(9997),

    FORWARD(9998),

    BROADCAST(9999), //TODO: rename for clarity, split this enum

    STATUS(10000),

    LOGIN(10001),

    PROXY_LOGIN(10002),

    LOGOUT(10003),

    SIGN(10004),

    VERIFY(10005),

    HASHES(10006),

    RESET_HASHES(10007),

    TERMS(10008),

    DEPLOY(20000),

    CREATE_ACCOUNT(20001),

    CALL(20002),

    BALANCE(20003),

    TRANSFER(20004),

    CONTRACT_STATE(20005),

    BROADCAST_BLOCK(20006),

    BROADCAST_CHAIN(20007),

    BROADCAST_MSG(20008),

    UPDATE_FEES(20009),

    WITHDRAW(20010),

    WITHDRAW_AUTH(20011),

    ISSUE_CREDENTIALS(25001),

    VERIFY_CREDENTIALS(25002),

    CREATE_PRESENTATION(25003),

    SIGN_PRESENTATION(25004),

    VERIFY_PRESENTATION(25005),

    VERIFY_DATA_SIGNATURE(25006),

    GRANT_ROLE(30000),

    GET_SIDECHAIN_DETAILS(30001),

    GET_USER_DETAILS(30002),

    GET_NODES(30003),

    GET_SCOPES(30004),

    GET_TABLES(30005),

    GET_TABLE_DEFINITION(30006),

    GET_NODE_CONFIG(30007),

    GET_ACCOUNT_NOTIFICATIONS(30008),

    UPDATE_LAYOUT(30009),

    UPDATE_CONFIG(30010),

    CREATE_USER_ACCOUNT(30011),

    PEER_STATUS(30012),

    THRESHOLD_SIG_ROUND_1(30013),

    THRESHOLD_SIG_ROUND_2(30014),

    READ_THRESHOLD_SIG_PUB_KEY(30015),

    SET_THRESHOLD_SIG_PUB_KEY(30016),

    SPLIT_LEARN(30017),

    GET_IMAGE(30018),

    PLUGIN(40000),
    ;


    @Getter
    private final int value;

    ApiOperationType(int value) {
        this.value = value;
    }

    public static ApiOperationType mapDataOperations(ApiOperationType type) {
        if (READ_TABLE_LAYOUT.equals(type)
            || COUNT.equals(type)
        ) {
            return VIEW;
        } else {
            return type;
        }
    }

    public static ApiOperationType mapPermission(String name) {
        if ("create".equals(name.toLowerCase(Locale.ROOT))) {
            return CREATE_TABLE;
        } else if ("drop".equals(name.toLowerCase(Locale.ROOT))) {
            return DROP_TABLE;
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
        } else if ("blacklist".equals(name.toLowerCase(Locale.ROOT))) {
            return BLACKLIST;
        } else if ("delete".equals(name.toLowerCase(Locale.ROOT))) {
            return DELETE;
        } else {
            return null;
        }
    }
}