package com.weavechain.api.mainchain;

import java.util.List;

public interface DatasetFilter {

    String getSidechainPublicKey();

    String getScopeName();

    String getDescription();

    List<String> getTags();

    String getDID();

    Boolean isStream();

    Long getCreatedAtUTCMs();

    //TODO: add other possible relevant fields
    // - last updated
    // - pricing details
}
