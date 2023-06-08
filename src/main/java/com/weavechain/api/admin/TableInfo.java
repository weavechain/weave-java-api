package com.weavechain.api.admin;

import com.weavechain.core.data.DataLayout;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class TableInfo {

    private final String id;

    private final String name;

    private final String creator;

    private final String creatorPublicKey;

    private final String creationDate;

    private final String scope;

    private final String timestamp;

    private final DataLayout layout;

    private final List<String> rights;

    private final Object data;

    private final Integer previewRowsCount;

    private final String access;
}