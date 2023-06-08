package com.weavechain.api.mainchain;

import java.util.List;

public interface DatasetMetadata {

    String getCreatorAccount();

    String getDID();

    String getName(); //consider handling markdown

    String getDescription(); //consider handling markdown

    List<String> getTags();

    boolean isStream();

    String getSidechainPublicKey();

    String getScope();

    Long getCreatedAtUTCMs();

    byte[] getSample();

    boolean isMatching(DatasetFilter filter);

    //TODO: add other possible relevant fields
    // - last updated
    // - pricing details
    // - number of participants/writers, maybe number of readers
    // - add data stats (number of rows, approx size)
    // - add historical payments stats
    // - add edit history (for the description metadata)
}
