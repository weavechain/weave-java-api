package com.weavechain.api.mainchain;

public interface SidechainMetadata {

    String getAccount();

    String getName();

    String getDescription();

    byte[] getLogo();

    Long getCreatedAtUTCMs();
}
