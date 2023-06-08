package com.weavechain.api.mainchain;

public interface AccountMetadata {

    String getAccount();

    String getName();

    byte[] getAvatar();

    String getDescription();

    Long getCreatedAtUTCMs();
}
