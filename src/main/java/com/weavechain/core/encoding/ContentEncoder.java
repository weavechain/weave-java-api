package com.weavechain.core.encoding;

import com.weavechain.core.data.DataLayout;
import com.weavechain.core.data.Records;

import java.io.IOException;

public interface ContentEncoder {

    String getType();

    String encode(Records data, DataLayout layout);

    Records decode(String data, DataLayout layout) throws IOException;
}