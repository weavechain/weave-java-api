package com.weavechain.core.consensus;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ConsensusMessage {

    private MessageType type;

    private String organization;

    private String account;

    private String scope;

    private String table;

    private Long seqNum;

    private String signerId;

    private String hash;

    private Long viewId;

    private Long blockId;

    private String action;

    private Map<String, Object> data = new HashMap<>();
}